//! An example escrow controller: an arbiter that lets one named judge decide a job.
//!
//! The buyer opens a job through the arbiter and names a judge. The arbiter records the case in
//! its own case account, derived from the job account, and opens the escrow job naming itself as
//! the controller. From then on the judge, and only the judge, can make the arbiter release part
//! of the deposit to the provider or return the job to the buyer. The parties still claim and
//! refund directly on the escrow.
//!
//! LEZ v0.4 delivers each message to one actor. The buyer's `Open` and the judge's `Decide` reach
//! their own actors under the arbiter, where `is_authorized` says whether they signed. Those
//! actors pass the case on to the case's actor, which only the arbiter itself can reach, and which
//! calls the escrow. A refusal anywhere fails the whole transaction, escrow call included.

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    Timestamp,
    account::{AccountId, Actor, Balance},
    program::{PdaSeed, ReceiveInput, Response, SyncMessage},
};
use logos_escrow_core::{Hash32, Instruction as EscrowInstruction, job_account_id};
use risc0_zkvm::sha::{Impl, Sha256 as _};

/// Domain separator for the case account's PDA seed.
const CASE_SEED_DOMAIN: &[u8; 32] = b"/logos-escrow/v2/ArbiterCase/000";

/// The case account of the escrow job account `job`, under the arbiter deployed at `arbiter`.
#[must_use]
pub fn case_account_id(arbiter: &AccountId, job: &AccountId) -> AccountId {
    AccountId::for_public_pda(arbiter, &case_seed(job))
}

fn case_seed(job: &AccountId) -> PdaSeed {
    let mut bytes = [0_u8; 64];
    bytes[..32].copy_from_slice(CASE_SEED_DOMAIN);
    bytes[32..].copy_from_slice(job.value());
    PdaSeed::new(
        Impl::hash_bytes(&bytes)
            .as_bytes()
            .try_into()
            .expect("sha256 is 32 bytes"),
    )
}

/// The arbiter's instructions, borsh-encoded.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum ArbiterInstruction {
    /// Opens an escrow job with this arbiter as its controller and `judge` deciding it. The other
    /// fields are the escrow's `Open`. To `Actor(buyer, arbiter)`, signed by the buyer.
    Open {
        escrow: AccountId,
        judge: AccountId,
        job_ref: Hash32,
        provider: AccountId,
        pay_to: AccountId,
        refund_to: AccountId,
        amount: Balance,
        deadline: Timestamp,
    },
    /// The judge's decision on the job of `buyer` and `job_ref`. To `Actor(judge, arbiter)`,
    /// signed by the judge, as a direct call.
    Decide {
        escrow: AccountId,
        buyer: AccountId,
        job_ref: Hash32,
        decision: Decision,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Decision {
    /// Lets the provider claim `amount` more.
    Release { amount: Balance },
    /// Gives what was never released back to the buyer.
    Return,
}

/// What the case account holds.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Case {
    pub escrow: AccountId,
    pub judge: AccountId,
    pub buyer: AccountId,
    pub provider: AccountId,
    pub job_ref: Hash32,
}

/// Why the arbiter refused a call. The guest exits with [`ArbiterError::code`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArbiterError {
    /// The message does not decode.
    InvalidInstruction,
    /// The buyer or the judge did not sign.
    Unauthorized,
    /// The case account is not the one derived from the escrow's job account for the buyer and
    /// the job reference.
    WrongCase,
    /// `Open` found a case already.
    CaseExists,
    /// The signer is not the case's judge.
    WrongJudge,
    /// The escrow is not the case's.
    WrongEscrow,
    /// The case account holds no case.
    NoCase,
    /// Another program called `Decide`. LEZ carries a signature into every program call, so a
    /// program the judge signs for could otherwise decide the judge's cases.
    NotDirect,
}

impl ArbiterError {
    /// The guest's exit code, above the escrow's (1 to 11) so a refusal says which program
    /// refused.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::InvalidInstruction => 101,
            Self::Unauthorized => 102,
            Self::WrongCase => 103,
            Self::CaseExists => 104,
            Self::WrongJudge => 105,
            Self::WrongEscrow => 106,
            Self::NoCase => 107,
            Self::NotDirect => 108,
        }
    }
}

/// What the arbiter's own actors pass to a case's actor. Only the arbiter sends it.
#[derive(BorshSerialize, BorshDeserialize)]
enum ToCase {
    /// Records a new case.
    Record(Case),
    /// The signer's decision, to check against the case and carry out.
    Decide {
        escrow: AccountId,
        judge: AccountId,
        decision: Decision,
    },
}

/// Handles one message to one of the arbiter's actors.
pub fn handle(input: &ReceiveInput) -> Result<Response, ArbiterError> {
    if input.from_own_program() {
        let message =
            borsh::from_slice(&input.message).map_err(|_| ArbiterError::InvalidInstruction)?;
        on_case(input, message)
    } else {
        let instruction =
            borsh::from_slice(&input.message).map_err(|_| ArbiterError::InvalidInstruction)?;
        on_signer(input, instruction)
    }
}

/// The buyer's `Open` or the judge's `Decide`, at the signer's own actor.
fn on_signer(
    input: &ReceiveInput,
    instruction: ArbiterInstruction,
) -> Result<Response, ArbiterError> {
    let arbiter = input.receiver.program_account_id;
    let signer = input.receiver.account_id;
    if !input.is_authorized {
        return Err(ArbiterError::Unauthorized);
    }
    match instruction {
        ArbiterInstruction::Open {
            escrow,
            judge,
            job_ref,
            provider,
            pay_to,
            refund_to,
            amount,
            deadline,
        } => {
            // Only the escrow's own job account for this buyer gets a case, so nobody can take
            // the case of someone else's job through an escrow of their own.
            let job = job_account_id(&escrow, &signer, &job_ref);
            let case = Case {
                escrow,
                judge,
                buyer: signer,
                provider,
                job_ref,
            };
            // The buyer's signature carries into this call, and the escrow takes it only because
            // the job names this program, the caller, as its controller.
            Ok(Response::keep_state()
                .send(to_case(arbiter, &job, &ToCase::Record(case)))
                .send_sync(
                    Actor::new(signer, escrow),
                    &EscrowInstruction::Open {
                        job_ref,
                        provider,
                        pay_to,
                        refund_to,
                        amount,
                        deadline,
                        controller: Some(arbiter),
                    },
                ))
        }
        ArbiterInstruction::Decide {
            escrow,
            buyer,
            job_ref,
            decision,
        } => {
            if input.from.is_some() {
                return Err(ArbiterError::NotDirect);
            }
            let job = job_account_id(&escrow, &buyer, &job_ref);
            Ok(Response::keep_state().send(to_case(
                arbiter,
                &job,
                &ToCase::Decide {
                    escrow,
                    judge: signer,
                    decision,
                },
            )))
        }
    }
}

/// A message to the case of `job`, with the case's seed: LEZ admits a fresh public account only
/// for the program whose PDA it is.
fn to_case(arbiter: AccountId, job: &AccountId, message: &ToCase) -> SyncMessage {
    SyncMessage::new(Actor::new(case_account_id(&arbiter, job), arbiter), message)
        .with_pda_seeds([case_seed(job)])
}

/// A message at a case's actor: records the case, or checks a decision against it and calls the
/// escrow.
fn on_case(input: &ReceiveInput, message: ToCase) -> Result<Response, ArbiterError> {
    let arbiter = input.receiver.program_account_id;
    match message {
        ToCase::Record(case) => {
            let job = job_account_id(&case.escrow, &case.buyer, &case.job_ref);
            if input.receiver.account_id != case_account_id(&arbiter, &job) {
                return Err(ArbiterError::WrongCase);
            }
            if !input.pre_state.is_empty() {
                return Err(ArbiterError::CaseExists);
            }
            Ok(Response::set_state(
                borsh::to_vec(&case).expect("a case serializes"),
            ))
        }
        ToCase::Decide {
            escrow,
            judge,
            decision,
        } => {
            if input.pre_state.is_empty() {
                return Err(ArbiterError::NoCase);
            }
            let case: Case =
                borsh::from_slice(&input.pre_state).map_err(|_| ArbiterError::NoCase)?;
            let job = job_account_id(&case.escrow, &case.buyer, &case.job_ref);
            if input.receiver.account_id != case_account_id(&arbiter, &job) {
                return Err(ArbiterError::WrongCase);
            }
            if case.escrow != escrow {
                return Err(ArbiterError::WrongEscrow);
            }
            if case.judge != judge {
                return Err(ArbiterError::WrongJudge);
            }
            let (party, instruction) = match decision {
                Decision::Release { amount } => (
                    case.buyer,
                    EscrowInstruction::Release {
                        job_ref: case.job_ref,
                        amount,
                    },
                ),
                Decision::Return => (
                    case.provider,
                    EscrowInstruction::Return {
                        buyer: case.buyer,
                        job_ref: case.job_ref,
                    },
                ),
            };
            Ok(Response::keep_state().send_sync(Actor::new(party, case.escrow), &instruction))
        }
    }
}
