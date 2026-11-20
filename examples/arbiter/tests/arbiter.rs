//! Every refusal of the example arbiter, through its handler the way LEZ v0.4 delivers messages:
//! a signer's call at its own actor, then the message that actor passes to the case's actor. The
//! happy paths run on LEZ's state machine in `integration/tests/flows.rs`.

use lee_core::{
    account::{AccountId, Actor, ActorState},
    program::{ReceiveInput, Response, SyncMessage},
};
use logos_escrow_arbiter::{
    ArbiterError, ArbiterInstruction, Case, Decision, case_account_id, handle,
};
use logos_escrow_core::{Instruction as EscrowInstruction, job_account_id};

const ARBITER: AccountId = AccountId::new([0xA7; 32]);
const ESCROW: AccountId = AccountId::new([0xE5; 32]);
const FAKE_ESCROW: AccountId = AccountId::new([0xFE; 32]);
const BUYER: AccountId = AccountId::new([1; 32]);
const PROVIDER: AccountId = AccountId::new([2; 32]);
const JUDGE: AccountId = AccountId::new([3; 32]);
const ATTACKER: AccountId = AccountId::new([4; 32]);
const JOB_REF: [u8; 32] = [9; 32];

fn job() -> AccountId {
    job_account_id(&ESCROW, &BUYER, &JOB_REF)
}

fn case() -> AccountId {
    case_account_id(&ARBITER, &job())
}

/// Runs `instruction` at `signer`'s own actor under the arbiter.
fn at_signer(
    signer: AccountId,
    signed: bool,
    caller: Option<AccountId>,
    instruction: &ArbiterInstruction,
) -> Result<Response, ArbiterError> {
    handle(&ReceiveInput {
        receiver: Actor::new(signer, ARBITER),
        from: caller.map(|caller| Actor::new(caller, caller)),
        is_authorized: signed,
        pre_state: ActorState::empty(),
        message: borsh::to_vec(instruction).expect("serializes"),
    })
}

/// The message a signer's actor sent to a case.
fn to_case(sent: &Response) -> &SyncMessage {
    sent.sync_messages
        .iter()
        .find(|message| message.to.program_account_id == ARBITER)
        .expect("a message to a case")
}

/// That message, run at the case's actor holding `pre`.
fn at_case(signer: AccountId, sent: &Response, pre: &[u8]) -> Result<Response, ArbiterError> {
    let message = to_case(sent);
    handle(&ReceiveInput {
        receiver: message.to,
        from: Some(Actor::new(signer, ARBITER)),
        is_authorized: true,
        pre_state: ActorState::from(pre.to_vec()),
        message: message.message.clone(),
    })
}

fn open(escrow: AccountId) -> ArbiterInstruction {
    ArbiterInstruction::Open {
        escrow,
        judge: JUDGE,
        job_ref: JOB_REF,
        provider: PROVIDER,
        pay_to: PROVIDER,
        refund_to: BUYER,
        amount: 500,
        deadline: 1_800_000_000_000,
    }
}

/// The case right after the buyer opened the job.
fn opened() -> Vec<u8> {
    let sent = at_signer(BUYER, true, None, &open(ESCROW)).expect("open");
    at_case(BUYER, &sent, &[])
        .expect("the case records")
        .post_state
        .expect("a case")
        .into_inner()
}

fn decide(escrow: AccountId, decision: Decision) -> ArbiterInstruction {
    ArbiterInstruction::Decide {
        escrow,
        buyer: BUYER,
        job_ref: JOB_REF,
        decision,
    }
}

fn release(escrow: AccountId) -> ArbiterInstruction {
    decide(escrow, Decision::Release { amount: 100 })
}

#[test]
fn open_records_the_case_and_opens_the_job_naming_the_arbiter() {
    let sent = at_signer(BUYER, true, None, &open(ESCROW)).expect("open");
    assert_eq!(to_case(&sent).to, Actor::new(case(), ARBITER));
    assert!(sent.sync_messages.contains(&SyncMessage::new(
        Actor::new(BUYER, ESCROW),
        &EscrowInstruction::Open {
            job_ref: JOB_REF,
            provider: PROVIDER,
            pay_to: PROVIDER,
            refund_to: BUYER,
            amount: 500,
            deadline: 1_800_000_000_000,
            controller: Some(ARBITER),
        },
    )));
    let case: Case = borsh::from_slice(&opened()).expect("a case");
    assert_eq!(
        case,
        Case {
            escrow: ESCROW,
            judge: JUDGE,
            buyer: BUYER,
            provider: PROVIDER,
            job_ref: JOB_REF,
        }
    );
}

#[test]
fn open_needs_the_buyer_signature() {
    assert_eq!(
        at_signer(BUYER, false, None, &open(ESCROW)).map(drop),
        Err(ArbiterError::Unauthorized)
    );
}

#[test]
fn nobody_takes_a_case_for_someone_elses_job() {
    // The job comes from the signer, so an attacker's open, through any escrow, names a job and
    // a case of its own.
    for escrow in [ESCROW, FAKE_ESCROW] {
        let sent = at_signer(ATTACKER, true, None, &open(escrow)).expect("open");
        assert_ne!(to_case(&sent).to.account_id, case());
    }
    // And a case can't be recorded anywhere but its own account.
    let sent = at_signer(BUYER, true, None, &open(ESCROW)).expect("open");
    let message = to_case(&sent);
    let elsewhere = case_account_id(&ARBITER, &job_account_id(&ESCROW, &BUYER, &[8; 32]));
    assert_eq!(
        handle(&ReceiveInput {
            receiver: Actor::new(elsewhere, ARBITER),
            from: Some(Actor::new(BUYER, ARBITER)),
            is_authorized: true,
            pre_state: ActorState::empty(),
            message: message.message.clone(),
        })
        .map(drop),
        Err(ArbiterError::WrongCase)
    );
}

#[test]
fn a_case_is_opened_once() {
    let sent = at_signer(BUYER, true, None, &open(ESCROW)).expect("open");
    assert_eq!(
        at_case(BUYER, &sent, &opened()).map(drop),
        Err(ArbiterError::CaseExists)
    );
}

#[test]
fn only_the_cases_judge_decides_and_only_for_its_escrow() {
    let by_attacker = at_signer(ATTACKER, true, None, &release(ESCROW)).expect("plans");
    assert_eq!(
        at_case(ATTACKER, &by_attacker, &opened()).map(drop),
        Err(ArbiterError::WrongJudge)
    );
    let elsewhere = at_signer(JUDGE, true, None, &release(FAKE_ESCROW)).expect("plans");
    // A decision for another escrow names another job, and so another case, with no case in it.
    assert_ne!(to_case(&elsewhere).to.account_id, case());
    assert_eq!(
        at_case(JUDGE, &elsewhere, &[]).map(drop),
        Err(ArbiterError::NoCase)
    );
}

#[test]
fn the_judges_decision_reaches_the_right_party() {
    let release = at_signer(JUDGE, true, None, &release(ESCROW)).expect("plans");
    let to_buyer = at_case(JUDGE, &release, &opened()).expect("applies");
    assert_eq!(
        to_buyer.sync_messages,
        vec![SyncMessage::new(
            Actor::new(BUYER, ESCROW),
            &EscrowInstruction::Release {
                job_ref: JOB_REF,
                amount: 100,
            },
        )]
    );
    let give_back = at_signer(JUDGE, true, None, &decide(ESCROW, Decision::Return)).expect("plans");
    let to_provider = at_case(JUDGE, &give_back, &opened()).expect("applies");
    assert_eq!(
        to_provider.sync_messages,
        vec![SyncMessage::new(
            Actor::new(PROVIDER, ESCROW),
            &EscrowInstruction::Return {
                buyer: BUYER,
                job_ref: JOB_REF,
            },
        )]
    );
}

#[test]
fn a_decision_needs_the_judge_to_sign_directly() {
    assert_eq!(
        at_signer(JUDGE, false, None, &release(ESCROW)).map(drop),
        Err(ArbiterError::Unauthorized)
    );
    // LEZ carries the judge's signature into any program the judge signs for.
    assert_eq!(
        at_signer(JUDGE, true, Some(ATTACKER), &release(ESCROW)).map(drop),
        Err(ArbiterError::NotDirect)
    );
}

#[test]
fn only_the_arbiter_itself_reaches_a_case() {
    // Another program's message to a case's actor is a call from the case account, which can't
    // sign.
    let sent = at_signer(JUDGE, true, None, &release(ESCROW)).expect("plans");
    assert_eq!(
        handle(&ReceiveInput {
            receiver: to_case(&sent).to,
            from: Some(Actor::new(ATTACKER, ATTACKER)),
            is_authorized: false,
            pre_state: ActorState::from(opened()),
            message: borsh::to_vec(&release(ESCROW)).expect("serializes"),
        })
        .map(drop),
        Err(ArbiterError::Unauthorized)
    );
}

#[test]
fn a_decision_needs_a_case() {
    let sent = at_signer(JUDGE, true, None, &release(ESCROW)).expect("plans");
    assert_eq!(
        at_case(JUDGE, &sent, &[]).map(drop),
        Err(ArbiterError::NoCase)
    );
}

/// The codes a client reads a refusal by.
#[test]
fn arbiter_codes_are_stable() {
    let codes = [
        (ArbiterError::InvalidInstruction, 101),
        (ArbiterError::Unauthorized, 102),
        (ArbiterError::WrongCase, 103),
        (ArbiterError::CaseExists, 104),
        (ArbiterError::WrongJudge, 105),
        (ArbiterError::NoCase, 107),
        (ArbiterError::NotDirect, 108),
    ];
    for (error, code) in codes {
        assert_eq!(error.code(), code, "{error:?}");
    }
}

/// Arbiter refusals use codes the escrow's errors (1 to 11) never do, so a refusal says which
/// program refused.
#[test]
fn arbiter_codes_do_not_overlap_the_escrows() {
    for error in [
        ArbiterError::InvalidInstruction,
        ArbiterError::Unauthorized,
        ArbiterError::WrongCase,
        ArbiterError::CaseExists,
        ArbiterError::WrongJudge,
        ArbiterError::NoCase,
        ArbiterError::NotDirect,
    ] {
        assert!(error.code() > 100, "{error:?}");
    }
}
