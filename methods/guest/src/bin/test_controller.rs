//! A test-only controller program. It relays whatever escrow call it is given, to whatever
//! party's actor, with whatever PDA seeds, and checks nothing, so it must never be deployed
//! anywhere that matters. It exists so tests can drive the escrow through a real program call.
//!
//! Message: the borsh tuple `(escrow program id, party account, PDA seeds, instruction bytes)`.
//! It's sent to any actor of this program; the relay goes to `Actor(party, escrow)`.

use std::collections::BTreeSet;

use lee_core::{
    account::{AccountId, Actor},
    program::{PdaSeed, ReceiveInput, Response, SyncMessage},
};

type Relay = (AccountId, AccountId, Vec<[u8; 32]>, Vec<u8>);

lee_core::actor_entrypoint!(relay);

fn relay(_input: &ReceiveInput, (escrow, party, seeds, message): Relay) -> Response {
    Response::keep_state().send(SyncMessage {
        to: Actor::new(party, escrow),
        message,
        pda_seeds: seeds.into_iter().map(PdaSeed::new).collect::<BTreeSet<_>>(),
    })
}
