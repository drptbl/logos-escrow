//! Drives the escrow's handler the way LEZ v0.4 delivers messages: a party's instruction at its
//! own actor under the escrow, then the step that actor sends on to the job's actor.

use lee_core::{
    account::{AccountId, Actor, ActorState},
    native_token::{Message as NativeMessage, custody_transfer},
    program::{ReceiveInput, Response, SyncMessage},
};
use logos_escrow_core::{
    Decision, EscrowError, Instruction, Job, JobState, events, handle, job_account_id, job_seed,
};

const PROGRAM: AccountId = AccountId::new([7; 32]);
const BUYER: AccountId = AccountId::new([1; 32]);
const PROVIDER: AccountId = AccountId::new([2; 32]);
/// Where the provider is paid, and where the buyer gets the deposit back.
const PAY_TO: AccountId = AccountId::new([3; 32]);
const REFUND_TO: AccountId = AccountId::new([6; 32]);
const STRANGER: AccountId = AccountId::new([5; 32]);
const JOB_REF: [u8; 32] = [9; 32];
const AMOUNT: u128 = 500;
const DEADLINE: u64 = 1_800_000_000_000;
const RESULT: [u8; 32] = [4; 32];
/// The program a controlled job names, and one it doesn't.
const CONTROLLER: AccountId = AccountId::new([8; 32]);
/// The account whose actor under `CONTROLLER` the controlled job names.
const CONTROLLER_ACCOUNT: AccountId = AccountId::new([11; 32]);

/// The one actor a controlled job names as its controller.
const fn controller() -> Actor {
    Actor::new(CONTROLLER_ACCOUNT, CONTROLLER)
}
const OTHER_PROGRAM: AccountId = AccountId::new([10; 32]);

fn job() -> AccountId {
    job_account_id(&PROGRAM, &BUYER, &JOB_REF)
}

/// How a call reaches the party's actor.
#[derive(Clone, Copy)]
struct By {
    party: AccountId,
    signed: bool,
    caller: Option<AccountId>,
}

/// `party`, signing its own call.
const fn signed(party: AccountId) -> By {
    By {
        party,
        signed: true,
        caller: None,
    }
}

/// `party`'s actor, reached without its signature.
const fn unsigned(party: AccountId) -> By {
    By {
        party,
        signed: false,
        caller: None,
    }
}

/// `by`, as relayed by the program `caller`.
const fn from(caller: AccountId, by: By) -> By {
    By {
        caller: Some(caller),
        ..by
    }
}

/// Runs `instruction` at the party's own actor under the escrow, as LEZ delivers it.
fn at_party(by: By, instruction: &Instruction) -> Result<Response, EscrowError> {
    handle(&ReceiveInput {
        receiver: Actor::new(by.party, PROGRAM),
        from: by.caller.map(|caller| Actor::new(caller, caller)),
        is_authorized: by.signed,
        pre_state: ActorState::empty(),
        message: borsh::to_vec(instruction).expect("instruction serializes"),
    })
}

/// The step `party`'s actor sent to the job, run at the job's actor holding `pre`.
fn at_job(party: AccountId, sent: &Response, pre: &[u8]) -> Result<Response, EscrowError> {
    let step = sent
        .sync_messages
        .iter()
        .find(|message| message.to.program_account_id == PROGRAM)
        .expect("the party's actor sends a step to a job");
    handle(&ReceiveInput {
        receiver: step.to,
        from: Some(Actor::new(party, PROGRAM)),
        is_authorized: true,
        pre_state: ActorState::from(pre.to_vec()),
        message: step.message.clone(),
    })
}

/// Both hops: the call at the party's actor, then its step at the job's actor holding `pre`.
fn call(by: By, instruction: &Instruction, pre: &[u8]) -> Result<Response, EscrowError> {
    at_job(by.party, &at_party(by, instruction)?, pre)
}

/// The job record a step left.
fn record(response: &Response) -> Job {
    let state = response
        .post_state
        .clone()
        .expect("the job's actor writes its record");
    borsh::from_slice(&state.into_inner()).expect("record decodes")
}

fn bytes(response: &Response) -> Vec<u8> {
    response.post_state.clone().expect("a record").into_inner()
}

/// A payout from the job account, authorized by the job account's PDA seed.
fn payout(to: AccountId, amount: u128) -> SyncMessage {
    custody_transfer(job(), job_seed(&BUYER, &JOB_REF), to, amount)
}

fn open_controlled_by(controller: Option<Actor>) -> Instruction {
    Instruction::Open {
        job_ref: JOB_REF,
        provider: PROVIDER,
        pay_to: PAY_TO,
        refund_to: REFUND_TO,
        amount: AMOUNT,
        deadline: DEADLINE,
        controller,
    }
}

fn open() -> Instruction {
    open_controlled_by(None)
}

/// The job record right after a successful `Open`.
fn opened() -> Vec<u8> {
    bytes(&call(signed(BUYER), &open(), &[]).expect("open"))
}

/// The job record right after the buyer opened it naming `CONTROLLER`.
fn opened_controlled() -> Vec<u8> {
    bytes(&call(signed(BUYER), &open_controlled_by(Some(controller())), &[]).expect("open"))
}

fn deliver() -> Instruction {
    Instruction::Deliver {
        buyer: BUYER,
        job_ref: JOB_REF,
        result: RESULT,
        deadline: DEADLINE,
    }
}

fn delivered() -> Vec<u8> {
    bytes(&call(signed(PROVIDER), &deliver(), &opened()).expect("deliver"))
}

fn claim_of(amount: u128) -> Instruction {
    Instruction::Claim {
        buyer: BUYER,
        job_ref: JOB_REF,
        amount,
    }
}

fn claim() -> Instruction {
    claim_of(AMOUNT)
}

fn release_of(amount: u128) -> Instruction {
    Instruction::Release {
        job_ref: JOB_REF,
        amount,
    }
}

/// Releases everything.
fn release() -> Instruction {
    release_of(AMOUNT)
}

fn released() -> Vec<u8> {
    bytes(&call(signed(BUYER), &release(), &opened()).expect("release"))
}

fn refund_of(amount: u128, deadline: u64) -> Instruction {
    Instruction::Refund {
        job_ref: JOB_REF,
        amount,
        deadline,
    }
}

fn refund() -> Instruction {
    refund_of(AMOUNT, DEADLINE)
}

fn give_back() -> Instruction {
    Instruction::Return {
        buyer: BUYER,
        job_ref: JOB_REF,
    }
}

fn returned() -> Vec<u8> {
    bytes(&call(signed(PROVIDER), &give_back(), &opened()).expect("return"))
}

fn claimed() -> Vec<u8> {
    bytes(&call(signed(PROVIDER), &claim(), &delivered()).expect("claim"))
}

fn refunded() -> Vec<u8> {
    bytes(&call(signed(BUYER), &refund_of(AMOUNT, 0), &returned()).expect("refund"))
}

#[test]
fn open_locks_the_deposit_in_the_job_account_until_the_deadline() {
    let sent = at_party(signed(BUYER), &open()).expect("open plans");
    assert!(sent.sync_messages.contains(&SyncMessage::new(
        Actor::native_balance(BUYER),
        &NativeMessage::Transfer {
            to: job(),
            amount: AMOUNT
        },
    )));
    assert_eq!(sent.validity.timestamps.start(), None);
    assert_eq!(sent.validity.timestamps.end(), Some(DEADLINE));

    let applied = at_job(BUYER, &sent, &[]).expect("open applies to an empty job account");
    assert!(applied.sync_messages.is_empty());
    assert_eq!(
        record(&applied),
        Job {
            buyer: BUYER,
            provider: PROVIDER,
            pay_to: PAY_TO,
            refund_to: REFUND_TO,
            amount: AMOUNT,
            released: 0,
            claimed: 0,
            deadline: DEADLINE,
            state: JobState::Open,
            result: None,
            controller: None,
        }
    );
}

#[test]
fn the_step_reaches_the_job_with_its_seed() {
    // LEZ admits a fresh public account only for the program whose PDA it is.
    let sent = at_party(signed(BUYER), &open()).expect("open plans");
    let step = sent
        .sync_messages
        .iter()
        .find(|message| message.to.program_account_id == PROGRAM)
        .expect("a step");
    assert_eq!(step.to, Actor::new(job(), PROGRAM));
    assert!(step.pda_seeds.contains(&job_seed(&BUYER, &JOB_REF)));
}

#[test]
fn open_needs_the_buyer_signature() {
    assert_eq!(
        call(unsigned(BUYER), &open(), &[]).map(drop),
        Err(EscrowError::Unauthorized)
    );
}

#[test]
fn open_refuses_a_job_that_already_exists() {
    assert_eq!(
        call(signed(BUYER), &open(), &opened()).map(drop),
        Err(EscrowError::JobExists)
    );
}

#[test]
fn open_refuses_terms_that_cannot_settle() {
    let with = |provider, pay_to, refund_to, amount| Instruction::Open {
        job_ref: JOB_REF,
        provider,
        pay_to,
        refund_to,
        amount,
        deadline: DEADLINE,
        controller: None,
    };
    for terms in [
        with(PROVIDER, PAY_TO, REFUND_TO, 0),
        with(BUYER, PAY_TO, REFUND_TO, AMOUNT),
        with(PROVIDER, job(), REFUND_TO, AMOUNT),
        with(PROVIDER, PAY_TO, job(), AMOUNT),
    ] {
        assert_eq!(
            at_party(signed(BUYER), &terms).map(drop),
            Err(EscrowError::InvalidTerms),
            "{terms:?}"
        );
    }
}

#[test]
fn deliver_records_the_result_hash_before_the_deadline() {
    let sent = at_party(signed(PROVIDER), &deliver()).expect("deliver plans");
    assert_eq!(sent.validity.timestamps.end(), Some(DEADLINE));
    let applied = at_job(PROVIDER, &sent, &opened()).expect("deliver applies");
    assert!(applied.sync_messages.is_empty());
    let job = record(&applied);
    assert_eq!(
        (job.state, job.released, job.result),
        (JobState::Delivered, AMOUNT, Some(RESULT))
    );
}

#[test]
fn only_the_named_provider_can_deliver() {
    assert_eq!(
        call(unsigned(PROVIDER), &deliver(), &opened()).map(drop),
        Err(EscrowError::Unauthorized)
    );
    assert_eq!(
        call(signed(STRANGER), &deliver(), &opened()).map(drop),
        Err(EscrowError::WrongParty)
    );
}

#[test]
fn deliver_must_quote_the_job_deadline() {
    let later = Instruction::Deliver {
        buyer: BUYER,
        job_ref: JOB_REF,
        result: RESULT,
        deadline: DEADLINE + 1,
    };
    assert_eq!(
        call(signed(PROVIDER), &later, &opened()).map(drop),
        Err(EscrowError::WrongDeadline)
    );
}

#[test]
fn deliver_needs_an_open_job() {
    assert_eq!(
        call(signed(PROVIDER), &deliver(), &delivered()).map(drop),
        Err(EscrowError::WrongState)
    );
    assert_eq!(
        call(signed(PROVIDER), &deliver(), &[]).map(drop),
        Err(EscrowError::NoJob)
    );
}

#[test]
fn the_provider_claims_a_delivered_job_to_its_pay_to() {
    let sent = at_party(signed(PROVIDER), &claim()).expect("claim plans");
    assert_eq!(sent.validity.timestamps.end(), None);
    let applied = at_job(PROVIDER, &sent, &delivered()).expect("claim applies");
    assert_eq!(applied.sync_messages, vec![payout(PAY_TO, AMOUNT)]);
    let job = record(&applied);
    assert_eq!((job.state, job.claimed), (JobState::Delivered, AMOUNT));
}

#[test]
fn only_the_named_provider_can_claim() {
    assert_eq!(
        call(unsigned(PROVIDER), &claim(), &delivered()).map(drop),
        Err(EscrowError::Unauthorized)
    );
    assert_eq!(
        call(signed(STRANGER), &claim(), &delivered()).map(drop),
        Err(EscrowError::WrongParty)
    );
}

#[test]
fn claim_pays_any_part_of_what_is_released_and_unclaimed() {
    let after_release = bytes(&call(signed(BUYER), &release_of(200), &opened()).expect("release"));
    let part = call(signed(PROVIDER), &claim_of(150), &after_release).expect("partial claim");
    assert_eq!(part.sync_messages, vec![payout(PAY_TO, 150)]);
    let after_part = bytes(&part);
    for too_much in [0, 51, u128::MAX] {
        assert_eq!(
            call(signed(PROVIDER), &claim_of(too_much), &after_part).map(drop),
            Err(EscrowError::WrongAmount),
            "{too_much}"
        );
    }
    let rest = record(&call(signed(PROVIDER), &claim_of(50), &after_part).expect("the rest"));
    assert_eq!(
        (rest.state, rest.released, rest.claimed),
        (JobState::Open, 200, 200)
    );
}

#[test]
fn claim_needs_something_released() {
    assert_eq!(
        call(signed(PROVIDER), &claim(), &opened()).map(drop),
        Err(EscrowError::WrongAmount)
    );
    assert_eq!(
        call(signed(PROVIDER), &claim(), &claimed()).map(drop),
        Err(EscrowError::WrongAmount)
    );
}

#[test]
fn release_lets_the_provider_claim_part_of_an_open_job_without_moving_money() {
    let sent = at_party(signed(BUYER), &release_of(200)).expect("release plans");
    assert_eq!(sent.validity.timestamps.end(), None);
    let once = at_job(BUYER, &sent, &opened()).expect("applies");
    assert!(once.sync_messages.is_empty());
    let job = record(&once);
    assert_eq!(
        (job.state, job.released, job.claimed),
        (JobState::Open, 200, 0)
    );
    let twice = record(&call(signed(BUYER), &release_of(200), &bytes(&once)).expect("again"));
    assert_eq!((twice.state, twice.released), (JobState::Open, 400));
}

#[test]
fn release_cannot_exceed_what_is_left() {
    let after_200 = bytes(&call(signed(BUYER), &release_of(200), &opened()).expect("release"));
    let after_400 =
        bytes(&call(signed(BUYER), &release_of(200), &after_200).expect("release again"));
    for too_much in [0, 101, u128::MAX] {
        assert_eq!(
            call(signed(BUYER), &release_of(too_much), &after_400).map(drop),
            Err(EscrowError::WrongAmount),
            "{too_much}"
        );
    }
    let all = record(&call(signed(BUYER), &release_of(100), &after_400).expect("the rest"));
    assert_eq!(all.released, AMOUNT);
}

#[test]
fn a_delivered_job_has_nothing_left_to_release() {
    assert_eq!(
        call(signed(BUYER), &release_of(1), &delivered()).map(drop),
        Err(EscrowError::WrongState)
    );
}

#[test]
fn release_needs_the_buyer_signature() {
    assert_eq!(
        call(unsigned(BUYER), &release(), &opened()).map(drop),
        Err(EscrowError::Unauthorized)
    );
}

#[test]
fn the_provider_claims_a_released_job_to_its_pay_to() {
    let applied = call(signed(PROVIDER), &claim(), &released()).expect("claim");
    assert_eq!(applied.sync_messages, vec![payout(PAY_TO, AMOUNT)]);
    let job = record(&applied);
    assert_eq!((job.state, job.claimed), (JobState::Open, AMOUNT));
}

#[test]
fn the_buyer_takes_back_an_undelivered_job_from_the_deadline_on() {
    let sent = at_party(signed(BUYER), &refund()).expect("refund plans");
    assert_eq!(sent.validity.timestamps.start(), Some(DEADLINE));
    assert_eq!(sent.validity.timestamps.end(), None);
    let applied = at_job(BUYER, &sent, &opened()).expect("refund applies");
    assert_eq!(applied.sync_messages, vec![payout(REFUND_TO, AMOUNT)]);
    assert_eq!(record(&applied).state, JobState::Refunded);
}

#[test]
fn refund_needs_the_buyer_signature() {
    assert_eq!(
        call(unsigned(BUYER), &refund(), &opened()).map(drop),
        Err(EscrowError::Unauthorized)
    );
}

#[test]
fn refund_must_quote_the_job_deadline_and_amount() {
    assert_eq!(
        call(signed(BUYER), &refund_of(AMOUNT, DEADLINE - 1), &opened()).map(drop),
        Err(EscrowError::WrongDeadline)
    );
    assert_eq!(
        call(signed(BUYER), &refund_of(AMOUNT + 1, DEADLINE), &opened()).map(drop),
        Err(EscrowError::WrongAmount)
    );
}

#[test]
fn a_delivered_job_cannot_be_refunded() {
    assert_eq!(
        call(signed(BUYER), &refund(), &delivered()).map(drop),
        Err(EscrowError::WrongState)
    );
}

#[test]
fn malformed_calls_are_refused() {
    let garbage = ReceiveInput {
        receiver: Actor::new(BUYER, PROGRAM),
        from: None,
        is_authorized: true,
        pre_state: ActorState::empty(),
        message: vec![0xff],
    };
    assert_eq!(
        handle(&garbage).map(drop),
        Err(EscrowError::InvalidInstruction)
    );
    let step = ReceiveInput {
        from: Some(Actor::new(BUYER, PROGRAM)),
        receiver: Actor::new(job(), PROGRAM),
        ..garbage
    };
    assert_eq!(
        handle(&step).map(drop),
        Err(EscrowError::InvalidInstruction)
    );
}

#[test]
fn a_step_for_another_jobs_account_is_refused() {
    let sent = at_party(signed(BUYER), &open()).expect("open plans");
    let step = sent
        .sync_messages
        .iter()
        .find(|message| message.to.program_account_id == PROGRAM)
        .expect("a step");
    let elsewhere = job_account_id(&PROGRAM, &PROVIDER, &JOB_REF);
    assert_eq!(
        handle(&ReceiveInput {
            receiver: Actor::new(elsewhere, PROGRAM),
            from: Some(Actor::new(BUYER, PROGRAM)),
            is_authorized: true,
            pre_state: ActorState::empty(),
            message: step.message.clone(),
        })
        .map(drop),
        Err(EscrowError::WrongJobAccount)
    );
}

#[test]
fn only_the_escrow_itself_steps_a_job() {
    // A step's bytes, sent by another program, don't decode as an instruction.
    let sent = at_party(signed(BUYER), &open()).expect("open plans");
    let step = sent
        .sync_messages
        .iter()
        .find(|message| message.to.program_account_id == PROGRAM)
        .expect("a step");
    let at_the_job = |caller: AccountId, message: Vec<u8>| {
        handle(&ReceiveInput {
            receiver: Actor::new(job(), PROGRAM),
            from: Some(Actor::new(caller, caller)),
            is_authorized: true,
            pre_state: ActorState::from(opened_controlled()),
            message,
        })
    };
    assert_eq!(
        at_the_job(OTHER_PROGRAM, step.message.clone()).map(drop),
        Err(EscrowError::InvalidInstruction)
    );
    // An instruction there, even from the job's own controller, is the job account acting as a
    // party: as a buyer it names another job, and it isn't this job's provider.
    let release = at_the_job(CONTROLLER, borsh::to_vec(&release()).expect("serializes"))
        .expect("plans a step for the job account's own job");
    assert_eq!(
        at_job(job(), &release, &[]).map(drop),
        Err(EscrowError::NoJob)
    );
    let give_back = at_the_job(CONTROLLER, borsh::to_vec(&give_back()).expect("serializes"))
        .expect("plans a step for this job");
    assert_eq!(
        at_job(job(), &give_back, &opened_controlled()).map(drop),
        Err(EscrowError::WrongParty)
    );
}

/// Literals computed independently (Python `hashlib` and the borsh spec), so a caller that
/// reimplements the derivation and the encoding can check itself against these.
#[test]
fn the_job_account_and_instruction_layout_are_stable() {
    let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    assert_eq!(
        hex(job_seed(&BUYER, &JOB_REF).as_bytes()),
        "82f93aaaff0ed39ce06c69791bd64f06a3c4e8d97e1e44f2857a71bfbca0a504"
    );
    assert_eq!(
        hex(job().value()),
        "1fa6999db67e6acc47b26a123f282e33e37ad257f071ce550c6ab33c1879cecc"
    );
    assert_eq!(
        hex(&borsh::to_vec(&deliver()).expect("serializes")),
        concat!(
            "01",
            "0101010101010101010101010101010101010101010101010101010101010101",
            "0909090909090909090909090909090909090909090909090909090909090909",
            "0404040404040404040404040404040404040404040404040404040404040404",
            "00505c18a3010000"
        )
    );
    assert_eq!(
        hex(&borsh::to_vec(&open()).expect("serializes")),
        concat!(
            "00",
            "0909090909090909090909090909090909090909090909090909090909090909",
            "0202020202020202020202020202020202020202020202020202020202020202",
            "0303030303030303030303030303030303030303030303030303030303030303",
            "0606060606060606060606060606060606060606060606060606060606060606",
            "f4010000000000000000000000000000",
            "00505c18a3010000",
            "00"
        )
    );
    assert_eq!(
        hex(&borsh::to_vec(&release()).expect("serializes")),
        concat!(
            "03",
            "0909090909090909090909090909090909090909090909090909090909090909",
            "f4010000000000000000000000000000"
        )
    );
    assert_eq!(
        hex(&borsh::to_vec(&give_back()).expect("serializes")),
        concat!(
            "05",
            "0101010101010101010101010101010101010101010101010101010101010101",
            "0909090909090909090909090909090909090909090909090909090909090909"
        )
    );
}

/// A decision sent straight to the job's actor by `sender`, or by the transaction itself.
fn decide(sender: Option<Actor>, decision: Decision, pre: &[u8]) -> Result<Response, EscrowError> {
    handle(&ReceiveInput {
        receiver: Actor::new(job(), PROGRAM),
        from: sender,
        is_authorized: false,
        pre_state: ActorState::from(pre.to_vec()),
        message: borsh::to_vec(&Instruction::Decide {
            buyer: BUYER,
            job_ref: JOB_REF,
            decision,
        })
        .expect("serializes"),
    })
}

#[test]
fn a_direct_open_may_name_any_controller() {
    let job: Job = borsh::from_slice(&opened_controlled()).expect("a record");
    assert_eq!(job.controller, Some(controller()));
}

/// Literals from the borsh spec, for callers that decode a job record or encode `Open` with a
/// controller themselves.
#[test]
fn the_job_record_and_controlled_open_layout_are_stable() {
    let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    assert_eq!(
        hex(&opened_controlled()),
        concat!(
            "0101010101010101010101010101010101010101010101010101010101010101",
            "0202020202020202020202020202020202020202020202020202020202020202",
            "0303030303030303030303030303030303030303030303030303030303030303",
            "0606060606060606060606060606060606060606060606060606060606060606",
            "f4010000000000000000000000000000",
            "00000000000000000000000000000000",
            "00000000000000000000000000000000",
            "00505c18a3010000",
            "00",
            "00",
            "01",
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "0808080808080808080808080808080808080808080808080808080808080808"
        )
    );
    assert!(
        hex(&borsh::to_vec(&open_controlled_by(Some(controller()))).expect("serializes"))
            .ends_with(concat!(
                "00505c18a3010000",
                "01",
                "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                "0808080808080808080808080808080808080808080808080808080808080808"
            ))
    );
    let decide = Instruction::Decide {
        buyer: BUYER,
        job_ref: JOB_REF,
        decision: Decision::Release { amount: AMOUNT },
    };
    assert_eq!(
        hex(&borsh::to_vec(&decide).expect("serializes")),
        concat!(
            "06",
            "0101010101010101010101010101010101010101010101010101010101010101",
            "0909090909090909090909090909090909090909090909090909090909090909",
            "00",
            "f4010000000000000000000000000000"
        )
    );
}

#[test]
fn a_program_may_only_open_a_job_one_of_its_actors_controls() {
    // The buyer's signature carries into the controller's call to the escrow.
    let itself = from(CONTROLLER, signed(BUYER));
    let applied = call(itself, &open_controlled_by(Some(controller())), &[]).expect("applies");
    assert_eq!(record(&applied).controller, Some(controller()));
    for named in [None, Some(Actor::new(CONTROLLER_ACCOUNT, OTHER_PROGRAM))] {
        assert_eq!(
            call(itself, &open_controlled_by(named), &[]).map(drop),
            Err(EscrowError::NotDirect),
            "{named:?}"
        );
    }
}

#[test]
fn the_controller_releases_and_returns_by_deciding_at_the_job() {
    let release = decide(
        Some(controller()),
        Decision::Release { amount: 200 },
        &opened_controlled(),
    )
    .expect("the controller releases");
    assert!(release.sync_messages.is_empty());
    assert_eq!(record(&release).released, 200);
    let give_back = decide(Some(controller()), Decision::Return, &opened_controlled())
        .expect("the controller returns");
    assert_eq!(record(&give_back).state, JobState::Returned);
}

#[test]
fn only_the_jobs_exact_controller_decides() {
    let release = Decision::Release { amount: 200 };
    let senders = [
        // The transaction itself, on a controlled job and on one with no controller.
        (None, opened_controlled()),
        (None, opened()),
        // Another actor of the controller's own program.
        (Some(Actor::new(STRANGER, CONTROLLER)), opened_controlled()),
        // The controller's account under another program.
        (
            Some(Actor::new(CONTROLLER_ACCOUNT, OTHER_PROGRAM)),
            opened_controlled(),
        ),
        // The controller, on a job that names none.
        (Some(controller()), opened()),
    ];
    for (sender, pre) in senders {
        assert_eq!(
            decide(sender, release, &pre).map(drop),
            Err(EscrowError::NotDirect),
            "{sender:?}"
        );
    }
}

#[test]
fn a_decision_names_its_job() {
    // At another job's actor, or at a party's.
    let elsewhere = ReceiveInput {
        receiver: Actor::new(job_account_id(&PROGRAM, &PROVIDER, &JOB_REF), PROGRAM),
        from: Some(controller()),
        is_authorized: false,
        pre_state: ActorState::from(opened_controlled()),
        message: borsh::to_vec(&Instruction::Decide {
            buyer: BUYER,
            job_ref: JOB_REF,
            decision: Decision::Return,
        })
        .expect("serializes"),
    };
    assert_eq!(
        handle(&elsewhere).map(drop),
        Err(EscrowError::WrongJobAccount)
    );
    let at_a_party = ReceiveInput {
        receiver: Actor::new(BUYER, PROGRAM),
        ..elsewhere
    };
    assert_eq!(
        handle(&at_a_party).map(drop),
        Err(EscrowError::WrongJobAccount)
    );
}

#[test]
fn a_program_cannot_act_on_a_job_it_does_not_control() {
    let calls = [
        (unsigned(BUYER), release()),
        (unsigned(PROVIDER), give_back()),
        (signed(PROVIDER), deliver()),
        (signed(PROVIDER), claim()),
        (signed(BUYER), refund()),
    ];
    for (by, instruction) in calls {
        // Another program, on a controlled job and on one with no controller.
        assert_eq!(
            call(from(OTHER_PROGRAM, by), &instruction, &opened_controlled()).map(drop),
            Err(EscrowError::NotDirect),
            "{instruction:?}"
        );
        assert_eq!(
            call(from(CONTROLLER, by), &instruction, &opened()).map(drop),
            Err(EscrowError::NotDirect),
            "{instruction:?}"
        );
    }
}

/// The controlled job after the controller released all of it.
fn released_controlled() -> Vec<u8> {
    bytes(
        &decide(
            Some(controller()),
            Decision::Release { amount: AMOUNT },
            &opened_controlled(),
        )
        .expect("release"),
    )
}

#[test]
fn a_party_call_always_needs_the_party() {
    // Through a party's actor even the controller's program needs the party: its decisions go
    // straight to the job instead. And only the side being paid pulls, so a payout pulled in a
    // public call to a private address can't be lost.
    let calls = [
        (unsigned(BUYER), release_of(200), opened_controlled()),
        (unsigned(PROVIDER), give_back(), opened_controlled()),
        (unsigned(PROVIDER), deliver(), opened_controlled()),
        (unsigned(PROVIDER), claim(), released_controlled()),
    ];
    for (by, instruction, pre) in calls {
        assert_eq!(
            call(from(CONTROLLER, by), &instruction, &pre).map(drop),
            Err(EscrowError::Unauthorized),
            "{instruction:?}"
        );
    }
    // A party the controller's program authorizes, such as its own PDA, still acts through it.
    let returned =
        bytes(&decide(Some(controller()), Decision::Return, &opened_controlled()).expect("return"));
    let refunded = call(
        from(CONTROLLER, signed(BUYER)),
        &refund_of(AMOUNT, 0),
        &returned,
    )
    .expect("refund");
    assert_eq!(record(&refunded).state, JobState::Refunded);
}

#[test]
fn nobody_releases_a_returned_job() {
    let returned =
        bytes(&decide(Some(controller()), Decision::Return, &opened_controlled()).expect("return"));
    assert_eq!(
        call(signed(BUYER), &release_of(1), &returned).map(drop),
        Err(EscrowError::WrongState)
    );
    assert_eq!(
        decide(
            Some(controller()),
            Decision::Release { amount: 1 },
            &returned
        )
        .map(drop),
        Err(EscrowError::WrongState)
    );
}

/// The event a response emitted, with its data decoded.
fn event<T: borsh::BorshDeserialize>(response: &Response, name: &str) -> T {
    let selector = events::selector(name);
    let found = response
        .events
        .iter()
        .find(|event| event.selector == selector)
        .unwrap_or_else(|| panic!("no {name} event"));
    borsh::from_slice(&found.data).expect("event data decodes")
}

/// Literals from Python's `hashlib`: the first 8 bytes of `sha256("logos_escrow::<Event>")`,
/// LEZ's convention for event selectors.
#[test]
fn event_selectors_are_stable() {
    let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    for (name, selector) in [
        ("Opened", "bd302df617c1685f"),
        ("Delivered", "a0cf04b66d2e0687"),
        ("Released", "95d8eff8ea992b74"),
        ("Claimed", "5273036ec2490250"),
        ("Returned", "a5eff4ddf518f44f"),
        ("Refunded", "604c2adf6947f950"),
    ] {
        assert_eq!(hex(&events::selector(name)), selector, "{name}");
    }
}

#[test]
fn every_change_to_a_job_emits_its_event() {
    let opened = call(signed(BUYER), &open_controlled_by(Some(controller())), &[]).expect("open");
    assert_eq!(
        event::<events::Opened>(&opened, "Opened"),
        events::Opened {
            job: job(),
            buyer: BUYER,
            provider: PROVIDER,
            amount: AMOUNT,
            deadline: DEADLINE,
            controller: Some(controller()),
        }
    );
    let delivered = call(signed(PROVIDER), &deliver(), &opened_controlled()).expect("deliver");
    assert_eq!(
        event::<events::Delivered>(&delivered, "Delivered"),
        events::Delivered {
            job: job(),
            result: RESULT,
        }
    );
    let released = decide(
        Some(controller()),
        Decision::Release { amount: 200 },
        &opened_controlled(),
    )
    .expect("release");
    assert_eq!(
        event::<events::Released>(&released, "Released"),
        events::Released {
            job: job(),
            amount: 200,
        }
    );
    let claimed = call(signed(PROVIDER), &claim_of(200), &bytes(&released)).expect("claim");
    assert_eq!(
        event::<events::Claimed>(&claimed, "Claimed"),
        events::Claimed {
            job: job(),
            to: PAY_TO,
            amount: 200,
        }
    );
    let returned = decide(Some(controller()), Decision::Return, &bytes(&released)).expect("return");
    assert_eq!(
        event::<events::Returned>(&returned, "Returned"),
        events::Returned { job: job() }
    );
    let refunded = call(
        signed(BUYER),
        &refund_of(AMOUNT - 200, 0),
        &bytes(&returned),
    )
    .expect("refund");
    assert_eq!(
        event::<events::Refunded>(&refunded, "Refunded"),
        events::Refunded {
            job: job(),
            to: REFUND_TO,
            amount: AMOUNT - 200,
        }
    );
}

#[test]
fn the_parties_still_act_directly_on_a_controlled_job() {
    let after_release =
        bytes(&call(signed(BUYER), &release_of(200), &opened_controlled()).expect("release"));
    let returned = call(signed(PROVIDER), &give_back(), &after_release).expect("return");
    assert_eq!(record(&returned).state, JobState::Returned);
}

#[test]
fn delivery_on_a_controlled_job_releases_nothing() {
    let after = bytes(&call(signed(PROVIDER), &deliver(), &opened_controlled()).expect("deliver"));
    let job: Job = borsh::from_slice(&after).expect("a record");
    assert_eq!(
        (job.state, job.released, job.result),
        (JobState::Open, 0, Some(RESULT))
    );
    // Once only.
    assert_eq!(
        call(signed(PROVIDER), &deliver(), &after).map(drop),
        Err(EscrowError::WrongState)
    );
    // The deadline still lets the buyer take everything back.
    let refunded = call(signed(BUYER), &refund(), &after).expect("refund");
    assert_eq!(refunded.sync_messages, vec![payout(REFUND_TO, AMOUNT)]);
}

#[test]
fn return_marks_an_open_job_refundable_without_moving_money() {
    let sent = at_party(signed(PROVIDER), &give_back()).expect("return plans");
    assert_eq!(sent.validity.timestamps.start(), None);
    assert_eq!(sent.validity.timestamps.end(), None);
    let applied = at_job(PROVIDER, &sent, &opened()).expect("return applies");
    assert!(applied.sync_messages.is_empty());
    assert_eq!(record(&applied).state, JobState::Returned);
}

#[test]
fn only_the_named_provider_can_return_a_job() {
    assert_eq!(
        call(unsigned(PROVIDER), &give_back(), &opened()).map(drop),
        Err(EscrowError::Unauthorized)
    );
    assert_eq!(
        call(signed(STRANGER), &give_back(), &opened()).map(drop),
        Err(EscrowError::WrongParty)
    );
}

#[test]
fn only_an_open_job_can_be_returned() {
    for pre in [delivered(), returned()] {
        assert_eq!(
            call(signed(PROVIDER), &give_back(), &pre).map(drop),
            Err(EscrowError::WrongState)
        );
    }
}

#[test]
fn the_buyer_refunds_a_returned_job_at_once_to_its_refund_to() {
    // After a return the deadline no longer applies, so the buyer passes 0.
    let sent = at_party(signed(BUYER), &refund_of(AMOUNT, 0)).expect("refund plans");
    assert_eq!(sent.validity.timestamps.start(), Some(0));
    let applied = at_job(BUYER, &sent, &returned()).expect("refund applies");
    assert_eq!(applied.sync_messages, vec![payout(REFUND_TO, AMOUNT)]);
    assert_eq!(record(&applied).state, JobState::Refunded);
    // On a job that wasn't returned, a refund still has to quote the deadline.
    assert_eq!(
        at_job(BUYER, &sent, &opened()).map(drop),
        Err(EscrowError::WrongDeadline)
    );
}

#[test]
fn refund_returns_only_what_was_never_released() {
    let after_release = bytes(&call(signed(BUYER), &release_of(200), &opened()).expect("release"));
    for wrong in [0, 299, AMOUNT] {
        assert_eq!(
            call(signed(BUYER), &refund_of(wrong, DEADLINE), &after_release).map(drop),
            Err(EscrowError::WrongAmount),
            "{wrong}"
        );
    }
    let refunded =
        call(signed(BUYER), &refund_of(300, DEADLINE), &after_release).expect("refund the rest");
    assert_eq!(refunded.sync_messages, vec![payout(REFUND_TO, 300)]);
    assert_eq!(record(&refunded).state, JobState::Refunded);
    // What was released before the refund is still the provider's to claim.
    let claimed =
        record(&call(signed(PROVIDER), &claim_of(200), &bytes(&refunded)).expect("claim"));
    assert_eq!(claimed.claimed, 200);
}

#[test]
fn nothing_released_cannot_be_claimed_and_nothing_left_cannot_be_refunded() {
    assert_eq!(
        call(signed(PROVIDER), &claim(), &returned()).map(drop),
        Err(EscrowError::WrongAmount)
    );
    assert_eq!(
        call(signed(BUYER), &refund(), &released()).map(drop),
        Err(EscrowError::WrongAmount)
    );
}

#[test]
fn a_payout_goes_to_the_jobs_own_address_whoever_asks() {
    // The record names the payee; nothing in a call can redirect it.
    let to_pay_to = call(signed(PROVIDER), &claim(), &delivered()).expect("claim");
    assert_eq!(to_pay_to.sync_messages, vec![payout(PAY_TO, AMOUNT)]);
    let to_refund_to = call(signed(BUYER), &refund(), &opened()).expect("refund");
    assert_eq!(to_refund_to.sync_messages, vec![payout(REFUND_TO, AMOUNT)]);
}

#[test]
fn a_finished_or_returned_job_cannot_be_released() {
    for pre in [claimed(), refunded(), returned()] {
        assert_eq!(
            call(signed(BUYER), &release(), &pre).map(drop),
            Err(EscrowError::WrongState)
        );
    }
}

#[test]
fn a_finished_job_cannot_be_refunded_again() {
    for pre in [claimed(), refunded()] {
        assert_eq!(
            call(signed(BUYER), &refund(), &pre).map(drop),
            Err(EscrowError::WrongState)
        );
    }
}

/// The codes a client reads a refusal by, as the README's error table numbers them.
#[test]
fn error_codes_are_stable() {
    let codes = [
        (EscrowError::InvalidInstruction, 1),
        (EscrowError::Unauthorized, 2),
        (EscrowError::WrongJobAccount, 3),
        (EscrowError::JobExists, 4),
        (EscrowError::InvalidTerms, 5),
        (EscrowError::WrongParty, 6),
        (EscrowError::WrongDeadline, 7),
        (EscrowError::NoJob, 8),
        (EscrowError::WrongState, 9),
        (EscrowError::WrongAmount, 10),
        (EscrowError::NotDirect, 11),
    ];
    for (error, code) in codes {
        assert_eq!(error.code(), code, "{error:?}");
    }
}

#[test]
fn the_job_takes_the_party_from_the_step_not_from_the_sender() {
    // A private sender shows up under a blinded alias, so the job's actor must not read `from`.
    let sent = at_party(signed(PROVIDER), &deliver()).expect("deliver plans");
    let step = sent
        .sync_messages
        .iter()
        .find(|message| message.to.program_account_id == PROGRAM)
        .expect("a step");
    let alias = AccountId::new([0xAA; 32]);
    let applied = handle(&ReceiveInput {
        receiver: step.to,
        from: Some(Actor::new(alias, PROGRAM)),
        is_authorized: true,
        pre_state: ActorState::from(opened()),
        message: step.message.clone(),
    })
    .expect("the provider's step applies whatever the sender's address");
    assert_eq!(record(&applied).state, JobState::Delivered);
}
