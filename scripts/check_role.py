#!/usr/bin/env python3
from pathlib import Path
import sys
text = Path('.ai-context.yml').read_text(encoding='utf-8')
need = [
    '  role: append_only_event_ledger',
    'role_contract:',
    '  name: append_only_event_ledger',
    '  authority: historical_evidence',
    '  unavailable_effect: new_event_capture_degrades',
    '    - no_worker_control',
    '    - no_orchestration_decisions',
]
for item in need:
    if item not in text:
        print(f'role-contract: missing {item!r}', file=sys.stderr)
        raise SystemExit(1)
if '  role: central_event_store' in text:
    print('role-contract: stale central_event_store role', file=sys.stderr)
    raise SystemExit(1)
print('role-contract: OK chronik')
