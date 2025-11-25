use chronik_producer::ProducerClient;
use serde::Serialize;
use std::env;

#[derive(Serialize)]
struct MyEvent {
 ts: String,
 source: &'static str,
 value: i32,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
 let token = env::var("CHRONIK_TOKEN").expect("CHRONIK_TOKEN must be set");
 let client = ProducerClient::new("http://localhost:7070", token);
 let e = MyEvent {
 ts: "2025-01-01T12:00:00Z".into(),
 source: "example",
 value: 42,
 };
 client.send_one(&e)?;
 println!("sent");
 Ok(())
}
