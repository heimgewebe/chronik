use chronik_producer::ProducerClient;
use serde::Serialize;

#[derive(Serialize)]
struct MyEvent {
 ts: String,
 source: &'static str,
 value: i32,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
 let client = ProducerClient::new("http://localhost:7070");
 let e = MyEvent {
 ts: "2025-01-01T12:00:00Z".into(),
 source: "example",
 value: 42,
 };
 client.send_one(&e)?;
 println!("sent");
 Ok(())
}
