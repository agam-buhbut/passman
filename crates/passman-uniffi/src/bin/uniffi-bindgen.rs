//! The uniffi-bindgen CLI entry point (feature `bindgen`). Generates the Kotlin
//! bindings from the compiled library's embedded metadata.
fn main() {
    uniffi::uniffi_bindgen_main();
}
