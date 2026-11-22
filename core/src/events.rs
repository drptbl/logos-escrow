//! The events the escrow emits, one for each change to a job, from the job's actor.
//!
//! An event is LEZ's `ProgramEvent`: an 8-byte selector, the first 8 bytes of
//! `sha256("logos_escrow::<Name>")`, and the Borsh bytes of the struct named here.

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    Timestamp,
    account::{AccountId, Actor, Balance},
    program::ProgramEvent,
};
use risc0_zkvm::sha::{Impl, Sha256 as _};

use crate::Hash32;

/// The selector of the event called `name`.
#[must_use]
pub fn selector(name: &str) -> [u8; 8] {
    let digest = Impl::hash_bytes(format!("logos_escrow::{name}").as_bytes());
    digest.as_bytes()[..8]
        .try_into()
        .expect("sha256 is 32 bytes")
}

pub(crate) fn emit<T: BorshSerialize>(name: &str, event: &T) -> ProgramEvent {
    ProgramEvent {
        selector: selector(name),
        data: borsh::to_vec(event).expect("an event serializes"),
    }
}

/// A job opened, with its terms.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Opened {
    pub job: AccountId,
    pub buyer: AccountId,
    pub provider: AccountId,
    pub amount: Balance,
    pub deadline: Timestamp,
    pub controller: Option<Actor>,
}

/// The provider recorded its result.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Delivered {
    pub job: AccountId,
    pub result: Hash32,
}

/// The buyer or the controller let the provider claim `amount` more.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Released {
    pub job: AccountId,
    pub amount: Balance,
}

/// The provider pulled `amount` to `to`, the job's `pay_to`.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Claimed {
    pub job: AccountId,
    pub to: AccountId,
    pub amount: Balance,
}

/// The provider or the controller gave the job up.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Returned {
    pub job: AccountId,
}

/// The buyer took `amount` back to `to`, the job's `refund_to`.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Refunded {
    pub job: AccountId,
    pub to: AccountId,
    pub amount: Balance,
}
