//! Job escrow for the Logos Execution Zone (LEZ v0.4).
//!
//! A buyer locks a payment for one job in a job account derived from the buyer and the job's
//! reference. The buyer releases it to the provider in parts, or the provider's delivery
//! releases all of it; the provider claims what is released. The buyer refunds what was never
//! released once the deadline passes, or once the provider returns the job.
//!
//! A job may name a controller program, such as a marketplace, a DAO or an arbiter. It may
//! release and return the job without the parties, and it decides what a delivery is worth: on a
//! controlled job, delivering releases nothing.
//!
//! LEZ v0.4 delivers each message to one actor, an account's state under a program. A party
//! sends its instruction to its own actor under the escrow, where `is_authorized` says whether it
//! signed and `from` names the program that called, if any. That actor passes the step on to the
//! job's actor, the job account's state under the escrow, which applies the job rules to the
//! record it holds. The job actor takes steps only from the escrow itself.

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    Timestamp,
    account::{AccountId, Actor, Balance},
    native_token::{Message as NativeMessage, custody_transfer},
    program::{PdaSeed, ReceiveInput, Response, SyncMessage, TimestampValidityWindow},
};
use risc0_zkvm::sha::{Impl, Sha256 as _};

pub mod events;
mod rules;

use rules::{Action, Origin};
pub use rules::{Job, JobState};

/// Domain separator for the job account's PDA seed.
const JOB_SEED_DOMAIN: &[u8; 32] = b"/lez-escrow/v1/JobSeed/000000000";

/// A 32-byte hash, such as a job reference or a result hash.
pub type Hash32 = [u8; 32];

/// The PDA seed of the job account for `buyer` and `job_ref`.
#[must_use]
pub fn job_seed(buyer: &AccountId, job_ref: &Hash32) -> PdaSeed {
    let mut bytes = [0_u8; 96];
    bytes[..32].copy_from_slice(JOB_SEED_DOMAIN);
    bytes[32..64].copy_from_slice(buyer.value());
    bytes[64..].copy_from_slice(job_ref);
    PdaSeed::new(
        Impl::hash_bytes(&bytes)
            .as_bytes()
            .try_into()
            .expect("sha256 is 32 bytes"),
    )
}

/// The job account for `buyer` and `job_ref` under the escrow program deployed at `program`.
#[must_use]
pub fn job_account_id(program: &AccountId, buyer: &AccountId, job_ref: &Hash32) -> AccountId {
    AccountId::for_public_pda(program, &job_seed(buyer, job_ref))
}

/// The escrow program's instructions, borsh-encoded as the message a party sends to its own
/// actor under the escrow: `Actor(buyer, escrow)` or `Actor(provider, escrow)`, as each says.
///
/// Money only ever moves to the addresses fixed at `Open`, and only when the side being paid
/// asks: the provider pulls with `Claim`, the buyer with `Refund`. `Release` and `Return` just
/// let the other side pull. So nobody pays into someone else's address, which in LEZ can burn a
/// private one or be blocked.
///
/// The parties sign their own calls. A program may call only for a job it controls: it may
/// `Release` and `Return` on its own, and every other instruction still needs the party it names
/// to be authorized, as the controller's own PDA would be.
///
/// A transaction declares every public actor it touches: the party's actor, the job's actor
/// `Actor(job, escrow)`, and for a call that moves lepta the native balances of both ends.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Instruction {
    /// Locks `amount` from the buyer for `provider` until `deadline`. The provider is paid to
    /// `pay_to` and the buyer gets the deposit back to `refund_to`. `controller` names the
    /// program that may act on the job besides the parties; a program opening a job must name
    /// itself. To `Actor(buyer, escrow)`, signed by the buyer.
    Open {
        job_ref: Hash32,
        provider: AccountId,
        pay_to: AccountId,
        refund_to: AccountId,
        amount: Balance,
        deadline: Timestamp,
        controller: Option<Actor>,
    },
    /// Records the provider's result hash, once, before the job's `deadline`. On a job without
    /// a controller it also releases everything left. To `Actor(provider, escrow)`.
    Deliver {
        buyer: AccountId,
        job_ref: Hash32,
        result: Hash32,
        deadline: Timestamp,
    },
    /// Pays `amount` to the job's `pay_to`, up to what is released and not yet claimed. To
    /// `Actor(provider, escrow)`.
    Claim {
        buyer: AccountId,
        job_ref: Hash32,
        amount: Balance,
    },
    /// Lets the provider claim `amount` more of an open job's deposit, up to all of it that is
    /// left. Moves no money. To `Actor(buyer, escrow)`.
    Release { job_ref: Hash32, amount: Balance },
    /// Pays the part of the deposit never released, which must be `amount`, back to the job's
    /// `refund_to`: from an open job's `deadline` on, or from a returned job at any time, when
    /// `deadline` is 0. To `Actor(buyer, escrow)`.
    Refund {
        job_ref: Hash32,
        amount: Balance,
        deadline: Timestamp,
    },
    /// The provider gives up an open job, so the buyer can refund what was never released at
    /// once. Moves no money. To `Actor(provider, escrow)`.
    Return { buyer: AccountId, job_ref: Hash32 },
    /// The controller's decision on the job of `buyer` and `job_ref`, sent straight to the job's
    /// actor `Actor(job, escrow)` from the exact actor the job names as its controller. Needs no
    /// party, so a private party being offline can't block it.
    Decide {
        buyer: AccountId,
        job_ref: Hash32,
        decision: Decision,
    },
}

/// What a controller decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Decision {
    /// Lets the provider claim `amount` more of the deposit, up to all of it that is left.
    Release { amount: Balance },
    /// Gives what was never released back to the buyer, who can refund it at once.
    Return,
}

/// Why the escrow program refused a call. The guest exits with [`EscrowError::code`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EscrowError {
    /// The message does not decode.
    InvalidInstruction,
    /// The party this instruction names did not authorize it.
    Unauthorized,
    /// The job account is not the one derived from the buyer and the job reference.
    WrongJobAccount,
    /// `Open` found a job record already in the job account.
    JobExists,
    /// `Open` with a zero amount, the buyer as its own provider, or the job account as a payout
    /// address.
    InvalidTerms,
    /// The party is not the job's buyer or provider as this instruction requires.
    WrongParty,
    /// The instruction's `deadline` is not the job's.
    WrongDeadline,
    /// The job account holds no job record.
    NoJob,
    /// The job is not in a state this instruction applies to.
    WrongState,
    /// The instruction's `amount` is zero, or more than it may release or claim, or not what a
    /// refund returns.
    WrongAmount,
    /// A program other than the job's controller called the escrow, or a program opened a job
    /// without naming itself. LEZ carries a signer's authorization into every chained call, so
    /// a program the parties sign for could otherwise act on their jobs.
    NotDirect,
}

impl EscrowError {
    /// The guest's exit code for this error.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::InvalidInstruction => 1,
            Self::Unauthorized => 2,
            Self::WrongJobAccount => 3,
            Self::JobExists => 4,
            Self::InvalidTerms => 5,
            Self::WrongParty => 6,
            Self::WrongDeadline => 7,
            Self::NoJob => 8,
            Self::WrongState => 9,
            Self::WrongAmount => 10,
            Self::NotDirect => 11,
        }
    }
}

/// A party's step, which its actor passes on to the job's actor. Only the escrow sends it.
#[derive(BorshSerialize, BorshDeserialize)]
struct Step {
    buyer: AccountId,
    job_ref: Hash32,
    origin: Origin,
    action: Action,
}

/// Handles one message to one of the escrow's actors: a party's instruction, a controller's
/// decision at a job, or a step the escrow passed on to a job.
pub fn handle(input: &ReceiveInput) -> Result<Response, EscrowError> {
    if input.from_own_program() {
        let step: Step =
            borsh::from_slice(&input.message).map_err(|_| EscrowError::InvalidInstruction)?;
        return at_job(input, step.buyer, step.job_ref, step.origin, step.action);
    }
    match borsh::from_slice(&input.message).map_err(|_| EscrowError::InvalidInstruction)? {
        Instruction::Decide {
            buyer,
            job_ref,
            decision,
        } => on_decide(input, buyer, job_ref, decision),
        instruction => on_party(input, instruction),
    }
}

/// A controller's decision, at the job's actor. Only the exact actor the job names gets past the
/// rules; a decision the transaction sent itself has no sender and never does.
fn on_decide(
    input: &ReceiveInput,
    buyer: AccountId,
    job_ref: Hash32,
    decision: Decision,
) -> Result<Response, EscrowError> {
    let origin = match input.from {
        Some(sender) => Origin::Controller(sender),
        None => return Err(EscrowError::NotDirect),
    };
    let action = match decision {
        Decision::Release { amount } => Action::Release { amount },
        // The provider's identity is the record's own: the job's actor fills it in.
        Decision::Return => Action::Return {
            provider: input.receiver.account_id,
        },
    };
    at_job(input, buyer, job_ref, origin, action)
}

/// A party's instruction at its own actor: turns it into the step for the job.
fn on_party(input: &ReceiveInput, instruction: Instruction) -> Result<Response, EscrowError> {
    let program = input.receiver.program_account_id;
    let party = input.receiver.account_id;
    let origin = Origin::Party {
        caller: input.from.map(|caller| caller.program_account_id),
        authorized: input.is_authorized,
    };
    // Claim and Refund pay the record's own addresses, which only the job's actor holds: it
    // replaces this with them.
    let from_the_record = party;
    // LEZ checks a deadline against the block's timestamp, which the job's actor can't do.
    let (buyer, job_ref, action, window, funding): (_, _, _, TimestampValidityWindow, _) =
        match instruction {
            Instruction::Open {
                job_ref,
                provider,
                pay_to,
                refund_to,
                amount,
                deadline,
                controller,
            } => {
                let job = job_account_id(&program, &party, &job_ref);
                if amount == 0 || provider == party || pay_to == job || refund_to == job {
                    return Err(EscrowError::InvalidTerms);
                }
                let record = Job {
                    buyer: party,
                    provider,
                    pay_to,
                    refund_to,
                    amount,
                    released: 0,
                    claimed: 0,
                    deadline,
                    state: JobState::Open,
                    result: None,
                    controller,
                };
                // The buyer's own balance, which its signature authorizes.
                let funding = SyncMessage::new(
                    Actor::native_balance(party),
                    &NativeMessage::Transfer { to: job, amount },
                );
                (
                    party,
                    job_ref,
                    Action::Open(record),
                    (..deadline).into(),
                    Some(funding),
                )
            }
            Instruction::Deliver {
                buyer,
                job_ref,
                result,
                deadline,
            } => (
                buyer,
                job_ref,
                Action::Deliver {
                    provider: party,
                    deadline,
                    result,
                },
                (..deadline).into(),
                None,
            ),
            Instruction::Claim {
                buyer,
                job_ref,
                amount,
            } => (
                buyer,
                job_ref,
                Action::Claim {
                    provider: party,
                    payee: from_the_record,
                    amount,
                },
                (..).into(),
                None,
            ),
            Instruction::Release { job_ref, amount } => (
                party,
                job_ref,
                Action::Release { amount },
                (..).into(),
                None,
            ),
            Instruction::Refund {
                job_ref,
                amount,
                deadline,
            } => (
                party,
                job_ref,
                Action::Refund {
                    payee: from_the_record,
                    amount,
                    deadline,
                },
                (deadline..).into(),
                None,
            ),
            // `handle` takes decisions to the job's actor.
            Instruction::Decide { .. } => unreachable!("a decision isn't a party's call"),
            Instruction::Return { buyer, job_ref } => (
                buyer,
                job_ref,
                Action::Return { provider: party },
                (..).into(),
                None,
            ),
        };
    let step = Step {
        buyer,
        job_ref,
        origin,
        action,
    };
    let response = Response::keep_state()
        .send(to_job(program, step))
        .timestamp_window(window);
    Ok(match funding {
        Some(funding) => response.send(funding),
        None => response,
    })
}

/// The step, sent to the job's actor with the job's seed: LEZ admits a fresh public account only
/// for the program whose PDA it is.
fn to_job(program: AccountId, step: Step) -> SyncMessage {
    let job = job_account_id(&program, &step.buyer, &step.job_ref);
    let seed = job_seed(&step.buyer, &step.job_ref);
    SyncMessage::new(Actor::new(job, program), &step).with_pda_seeds([seed])
}

/// At the job's actor: applies the job rules to its record, pays out what they allow, and emits
/// the change.
fn at_job(
    input: &ReceiveInput,
    buyer: AccountId,
    job_ref: Hash32,
    origin: Origin,
    action: Action,
) -> Result<Response, EscrowError> {
    let program = input.receiver.program_account_id;
    let job = input.receiver.account_id;
    if job != job_account_id(&program, &buyer, &job_ref) {
        return Err(EscrowError::WrongJobAccount);
    }
    let pre: Option<Job> = if input.pre_state.is_empty() {
        None
    } else {
        // Only this program writes its job records, so one that does not decode cannot happen.
        Some(borsh::from_slice(&input.pre_state).map_err(|_| EscrowError::NoJob)?)
    };
    // Payees, and a controller's provider, are the record's own.
    let action = match (action, &pre, origin) {
        (
            Action::Claim {
                provider, amount, ..
            },
            Some(record),
            _,
        ) => Action::Claim {
            provider,
            payee: record.pay_to,
            amount,
        },
        (
            Action::Refund {
                amount, deadline, ..
            },
            Some(record),
            _,
        ) => Action::Refund {
            payee: record.refund_to,
            amount,
            deadline,
        },
        (Action::Return { .. }, Some(record), Origin::Controller(_)) => Action::Return {
            provider: record.provider,
        },
        (action, _, _) => action,
    };
    let event = event(job, &action);
    let next = rules::step(pre, origin, action.clone())?;
    let response =
        Response::set_state(borsh::to_vec(&next).expect("a job record serializes")).event(event);
    let payout = match action {
        Action::Claim { amount, .. } => Some((next.pay_to, amount)),
        Action::Refund { amount, .. } => Some((next.refund_to, amount)),
        _ => None,
    };
    Ok(match payout {
        Some((payee, amount)) => response.send(custody_transfer(
            job,
            job_seed(&buyer, &job_ref),
            payee,
            amount,
        )),
        None => response,
    })
}

/// The event for `action` on `job`, once the rules allow it.
fn event(job: AccountId, action: &Action) -> lee_core::program::ProgramEvent {
    match action {
        Action::Open(record) => events::emit(
            "Opened",
            &events::Opened {
                job,
                buyer: record.buyer,
                provider: record.provider,
                amount: record.amount,
                deadline: record.deadline,
                controller: record.controller,
            },
        ),
        Action::Deliver { result, .. } => events::emit(
            "Delivered",
            &events::Delivered {
                job,
                result: *result,
            },
        ),
        Action::Release { amount } => events::emit(
            "Released",
            &events::Released {
                job,
                amount: *amount,
            },
        ),
        Action::Claim { payee, amount, .. } => events::emit(
            "Claimed",
            &events::Claimed {
                job,
                to: *payee,
                amount: *amount,
            },
        ),
        Action::Return { .. } => events::emit("Returned", &events::Returned { job }),
        Action::Refund { payee, amount, .. } => events::emit(
            "Refunded",
            &events::Refunded {
                job,
                to: *payee,
                amount: *amount,
            },
        ),
    }
}
