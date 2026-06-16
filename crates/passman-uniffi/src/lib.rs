//! UniFFI binding probe.
uniffi::setup_scaffolding!();

#[uniffi::export]
fn ping() -> String {
    "pong".to_owned()
}
