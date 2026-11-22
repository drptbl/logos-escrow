//! The escrow program's zkVM entry point. The rules live in `logos_escrow_core`; this only runs
//! its handler on the message LEZ delivers and writes the result.
//!
//! A refused call exits with the error's code instead of panicking: LEZ charges a non-zero exit
//! only for the cycles it used, but a panic for the transaction's whole cycle budget.

use lee_core::program::{ReceiveInput, Response};
use risc0_zkvm::guest::env;

// Raw, so a message that doesn't decode exits with its code too.
lee_core::actor_entrypoint!(raw handle);

fn handle(input: &ReceiveInput) -> Response {
    logos_escrow_core::handle(input).unwrap_or_else(|error| env::exit(error.code()))
}
