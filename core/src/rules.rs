//! The job rules, free of LEZ's program types, so a port to another LEZ program model only
//! rewrites the layer in `lib.rs` that feeds them, as the port from v0.3's plan/apply to v0.4's
//! actors did.

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    Timestamp,
    account::{AccountId, Actor, Balance},
};

use crate::{EscrowError, Hash32};

/// Where a job is in its life.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum JobState {
    /// The deposit is locked; the buyer may release parts of it.
    Open,
    /// The provider delivered, and everything is released.
    Delivered,
    /// The provider gave up the job; the buyer can refund what was never released.
    Returned,
    /// The buyer took back what was never released.
    Refunded,
}

/// The job record, held by the job account's actor under the escrow program.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Job {
    pub buyer: AccountId,
    pub provider: AccountId,
    /// Where `Claim` pays.
    pub pay_to: AccountId,
    /// Where `Refund` pays.
    pub refund_to: AccountId,
    /// The deposit.
    pub amount: Balance,
    /// How much of the deposit the provider may claim.
    pub released: Balance,
    /// How much the provider has claimed.
    pub claimed: Balance,
    /// Milliseconds since the Unix epoch.
    pub deadline: Timestamp,
    pub state: JobState,
    pub result: Option<Hash32>,
    /// The one actor, an account's state under a program, that may release and return this job
    /// besides its parties.
    pub controller: Option<Actor>,
}

impl Job {
    /// What the provider may claim now.
    #[must_use]
    pub const fn claimable(&self) -> Balance {
        self.released - self.claimed
    }

    /// What was never released: what `Release` may still release, and what `Refund` returns.
    #[must_use]
    pub const fn unreleased(&self) -> Balance {
        self.amount - self.released
    }
}

/// Who asked for an action.
#[derive(Debug, Clone, Copy, BorshSerialize, BorshDeserialize)]
pub enum Origin {
    /// A party's call: the program that called the escrow, or `None` when the transaction called
    /// it directly, and whether the party the action names authorized it.
    Party {
        caller: Option<AccountId>,
        authorized: bool,
    },
    /// A decision sent straight to the job by this actor.
    Controller(Actor),
}

/// One change to a job, with the values the caller quoted for the record to match.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
#[expect(
    clippy::large_enum_variant,
    reason = "one action lives for one call, so boxing the record would only add an allocation"
)]
pub enum Action {
    Open(Job),
    Deliver {
        provider: AccountId,
        deadline: Timestamp,
        result: Hash32,
    },
    Claim {
        provider: AccountId,
        payee: AccountId,
        amount: Balance,
    },
    Release {
        amount: Balance,
    },
    Refund {
        payee: AccountId,
        amount: Balance,
        deadline: Timestamp,
    },
    Return {
        provider: AccountId,
    },
}

/// Applies `action`, asked for by `origin`, to the job record `pre`, or to no record, and
/// returns the next record.
///
/// Every party call needs the party it names, so only the side being paid pulls a payout. A
/// program may only call for a job its controller belongs to, and may open a job only naming one
/// of its own actors. The job's controller, and only that exact actor, may `Release` and `Return`
/// on its own, by a decision sent straight to the job.
pub fn step(pre: Option<Job>, origin: Origin, action: Action) -> Result<Job, EscrowError> {
    // The new job's controller for `Open`, so a program opens a job only for itself.
    let controller = match (&action, &pre) {
        (Action::Open(job), _) | (_, Some(job)) => job.controller,
        (_, None) => return Err(EscrowError::NoJob),
    };
    match origin {
        Origin::Party { caller, authorized } => {
            if caller.is_some() && caller != controller.map(|actor| actor.program_account_id) {
                return Err(EscrowError::NotDirect);
            }
            if !authorized {
                return Err(EscrowError::Unauthorized);
            }
        }
        Origin::Controller(sender) => {
            if controller != Some(sender) {
                return Err(EscrowError::NotDirect);
            }
            if !matches!(action, Action::Release { .. } | Action::Return { .. }) {
                return Err(EscrowError::Unauthorized);
            }
        }
    }
    if let Action::Open(job) = action {
        return match pre {
            Some(_) => Err(EscrowError::JobExists),
            None => Ok(job),
        };
    }
    let Some(mut job) = pre else {
        return Err(EscrowError::NoJob);
    };
    match action {
        Action::Open(_) => unreachable!("handled above"),
        Action::Deliver {
            provider,
            deadline,
            result,
        } => {
            if job.provider != provider {
                return Err(EscrowError::WrongParty);
            }
            if job.deadline != deadline {
                return Err(EscrowError::WrongDeadline);
            }
            if job.state != JobState::Open {
                return Err(EscrowError::WrongState);
            }
            if job.result.is_some() {
                return Err(EscrowError::WrongState);
            }
            job.result = Some(result);
            // A controlled job's controller judges the result and releases what it decides.
            if job.controller.is_none() {
                job.released = job.amount;
                job.state = JobState::Delivered;
            }
        }
        Action::Claim {
            provider,
            payee,
            amount,
        } => {
            if job.provider != provider || job.pay_to != payee {
                return Err(EscrowError::WrongParty);
            }
            if amount == 0 || amount > job.claimable() {
                return Err(EscrowError::WrongAmount);
            }
            job.claimed += amount;
        }
        Action::Release { amount } => {
            if job.state != JobState::Open {
                return Err(EscrowError::WrongState);
            }
            // Bounded by what is left before adding, so it cannot overflow.
            if amount == 0 || amount > job.unreleased() {
                return Err(EscrowError::WrongAmount);
            }
            job.released += amount;
        }
        Action::Refund {
            payee,
            amount,
            deadline,
        } => {
            if job.refund_to != payee {
                return Err(EscrowError::WrongParty);
            }
            match job.state {
                // The window `deadline..` only holds the refund back if it is the job's deadline.
                JobState::Open if job.deadline != deadline => {
                    return Err(EscrowError::WrongDeadline);
                }
                JobState::Open | JobState::Returned => {}
                _ => return Err(EscrowError::WrongState),
            }
            if amount == 0 || amount != job.unreleased() {
                return Err(EscrowError::WrongAmount);
            }
            job.state = JobState::Refunded;
        }
        Action::Return { provider } => {
            if job.provider != provider {
                return Err(EscrowError::WrongParty);
            }
            if job.state != JobState::Open {
                return Err(EscrowError::WrongState);
            }
            job.state = JobState::Returned;
        }
    }
    Ok(job)
}
