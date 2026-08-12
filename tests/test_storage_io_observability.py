import pytest
from fastapi.testclient import TestClient

import app
import storage


class RecordingGauge:
    def __init__(self):
        self.value = 0
        self.events = []

    def inc(self):
        self.value += 1
        self.events.append("inc")

    def dec(self):
        self.value -= 1
        self.events.append("dec")


class RecordingHistogram:
    def __init__(self):
        self.operations = []
        self.values = []

    def labels(self, *, operation):
        self.operations.append(operation)
        return self

    def observe(self, value):
        self.values.append(value)


@pytest.mark.asyncio
async def test_storage_io_metrics_balance_success(monkeypatch):
    gauge = RecordingGauge()
    histogram = RecordingHistogram()
    monkeypatch.setattr(app, "storage_io_in_flight", gauge)
    monkeypatch.setattr(app, "storage_io_duration_seconds", histogram)

    result = await app._run_storage_io("events_scan", lambda value: value + 1, 4)

    assert result == 5
    assert gauge.value == 0
    assert gauge.events == ["inc", "dec"]
    assert histogram.operations == ["events_scan"]
    assert len(histogram.values) == 1
    assert histogram.values[0] >= 0.0


@pytest.mark.asyncio
async def test_storage_io_metrics_balance_failure(monkeypatch):
    gauge = RecordingGauge()
    histogram = RecordingHistogram()
    monkeypatch.setattr(app, "storage_io_in_flight", gauge)
    monkeypatch.setattr(app, "storage_io_duration_seconds", histogram)

    def fail():
        raise storage.StorageError("synthetic storage failure")

    with pytest.raises(storage.StorageError, match="synthetic storage failure"):
        await app._run_storage_io("latest_read", fail)

    assert gauge.value == 0
    assert gauge.events == ["inc", "dec"]
    assert histogram.operations == ["latest_read"]
    assert len(histogram.values) == 1


@pytest.mark.asyncio
async def test_storage_io_metric_backend_failure_does_not_change_result(monkeypatch):
    class BrokenGauge:
        def inc(self):
            raise RuntimeError("metrics unavailable")

        def dec(self):
            raise AssertionError("dec must not run after failed inc")

    class BrokenHistogram:
        def labels(self, **_labels):
            raise RuntimeError("metrics unavailable")

    monkeypatch.setattr(app, "storage_io_in_flight", BrokenGauge())
    monkeypatch.setattr(app, "storage_io_duration_seconds", BrokenHistogram())

    result = await app._run_storage_io("tail_read", lambda: "ok")

    assert result == "ok"


def test_metrics_endpoint_exposes_storage_io_series(monkeypatch, tmp_path):
    monkeypatch.setenv("CHRONIK_TOKEN", "test-token")
    monkeypatch.setenv("CHRONIK_INTEGRITY_ENABLED", "0")
    monkeypatch.setattr(storage, "DATA_DIR", tmp_path)
    app.limiter.reset()
    try:
        with TestClient(app.app) as client:
            response = client.get(
                "/v1/latest?domain=example.com",
                headers={"X-Auth": "test-token"},
            )
            assert response.status_code == 404

            metrics = client.get("/metrics")
            assert metrics.status_code == 200
            assert "chronik_storage_io_in_flight" in metrics.text
            assert (
                'chronik_storage_io_duration_seconds_count{operation="latest_read"}'
                in metrics.text
            )
    finally:
        app.limiter.reset()
