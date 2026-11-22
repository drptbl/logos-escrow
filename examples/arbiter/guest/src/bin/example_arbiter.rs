//! The example arbiter's zkVM entry point. Its rules live in `examples/arbiter`; this only runs
//! its handler on the message LEZ delivers. A refused call exits with the error's code, which LEZ
//! charges only for the cycles used.

use lee_core::program::{ReceiveInput, Response};
use risc0_zkvm::guest::env;

// Raw, so a message that doesn't decode exits with its code too.
lee_core::actor_entrypoint!(raw handle);

fn handle(input: &ReceiveInput) -> Response {
    logos_escrow_arbiter::handle(input).unwrap_or_else(|error| env::exit(error.code()))
}
