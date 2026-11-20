//! Runs the built escrow guest through LEZ v0.4's state machine, as the sequencer does: real
//! signatures, declared actors, program calls, PDA custody and validity windows.
//!
//! Needs the guest binaries: `make build`.

use std::{borrow::Cow, collections::BTreeMap};

use lee::{
    PrivateKey, PublicAccountEvidence, PublicKey, PublicTransaction, V03State,
    error::{InvalidProgramBehaviorError, LeeError},
    program::Program,
    public_transaction::{Message, WitnessSet},
};
use lee_core::{
    account::{AccountId, Actor, Balance},
    native_token::{Message as NativeMessage, TransferError},
    program::PdaSeed,
};
use logos_escrow_arbiter::{ArbiterInstruction, Decision, case_account_id};
use logos_escrow_core::{Instruction, Job, JobState, job_account_id};

const GUEST: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../methods/guest/target/riscv32im-risc0-zkvm-elf/docker/logos_escrow.bin"
);
/// The test-only controller, which relays whatever escrow call it is given.
const CONTROLLER_GUEST: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../methods/guest/target/riscv32im-risc0-zkvm-elf/docker/test_controller.bin"
);
/// The example arbiter controller.
const ARBITER_GUEST: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../examples/arbiter/guest/target/riscv32im-risc0-zkvm-elf/docker/example_arbiter.bin"
);
/// Where the test deploys the escrow program; on chain this is the header account.
const PROGRAM: AccountId = AccountId::new([0xE5; 32]);
const CONTROLLER: AccountId = AccountId::new([0xC0; 32]);
const ARBITER: AccountId = AccountId::new([0xA7; 32]);
const JOB_REF: [u8; 32] = [9; 32];
const AMOUNT: Balance = 500;
const START: Balance = 10_000;
const DEADLINE: u64 = 1_800_000_000_000;
const BEFORE: u64 = DEADLINE - 1;

struct Party {
    key: PrivateKey,
    id: AccountId,
}

impl Party {
    fn new(seed: u8) -> Self {
        let key = PrivateKey::try_new([seed; 32]).expect("valid key");
        let id = AccountId::from(&PublicKey::new_from_private_key(&key));
        Self { key, id }
    }
}

fn buyer() -> Party {
    Party::new(1)
}

fn provider() -> Party {
    Party::new(2)
}

/// Where the provider is paid and the buyer refunded: fresh public accounts, apart from the
/// parties. Paying into one takes its public key as admission evidence.
fn pay_to() -> Party {
    Party::new(3)
}

fn refund_to() -> Party {
    Party::new(4)
}

/// LEZ admits a fresh public account into a transaction only with its key.
fn evidence(party: &Party) -> PublicAccountEvidence {
    PublicAccountEvidence::Key(PublicKey::new_from_private_key(&party.key))
}

/// Signs calls to the controller; it is neither party.
fn operator() -> Party {
    Party::new(5)
}

fn job() -> AccountId {
    job_account_id(&PROGRAM, &buyer().id, &JOB_REF)
}

fn escrow(account: AccountId) -> Actor {
    Actor::new(account, PROGRAM)
}

fn native(account: AccountId) -> Actor {
    Actor::native_balance(account)
}

fn load(path: &str) -> Program {
    let elf = std::fs::read(path).unwrap_or_else(|error| {
        panic!("guest binary missing at {path} ({error}); build it with make build")
    });
    Program::new(Cow::Owned(elf)).expect("valid guest")
}

struct Chain {
    state: V03State,
    block: u64,
}

impl Chain {
    fn new() -> Self {
        let state = V03State::new()
            .with_public_account_balances([
                (buyer().id, START),
                (provider().id, START),
                (operator().id, START),
            ])
            .with_named_programs([
                (PROGRAM, load(GUEST)),
                (CONTROLLER, load(CONTROLLER_GUEST)),
                (ARBITER, load(ARBITER_GUEST)),
            ]);
        Self { state, block: 1 }
    }

    /// Sends `message` to `to`, declaring `actors`, admitting `fresh` and signed by `signer`.
    fn send<M: borsh::BorshSerialize>(
        &mut self,
        signer: &Party,
        to: Actor,
        actors: &[Actor],
        fresh: Vec<PublicAccountEvidence>,
        message: &M,
        timestamp: u64,
    ) -> Result<(), LeeError> {
        let nonce = self.state.get_account_by_id(signer.id).nonce;
        let nonces = BTreeMap::from([(signer.id, nonce)]);
        let tx = Message::new(
            to,
            Program::serialize_message(message)?,
            actors.iter().copied(),
            nonces,
            None,
            fresh,
        );
        let witness_set = WitnessSet::for_message(&tx, &[&signer.key]);
        self.block += 1;
        self.state
            .transition_from_public_transaction(
                &PublicTransaction::new(tx, witness_set),
                self.block,
                timestamp,
            )
            .map(drop)
    }

    /// One escrow call from `signer`'s own actor, declaring it, the job and `more`.
    fn call(
        &mut self,
        signer: &Party,
        instruction: &Instruction,
        more: &[Actor],
        timestamp: u64,
    ) -> Result<(), LeeError> {
        self.call_admitting(signer, instruction, more, Vec::new(), timestamp)
    }

    fn call_admitting(
        &mut self,
        signer: &Party,
        instruction: &Instruction,
        more: &[Actor],
        fresh: Vec<PublicAccountEvidence>,
        timestamp: u64,
    ) -> Result<(), LeeError> {
        let mut actors = vec![escrow(signer.id), escrow(job())];
        actors.extend_from_slice(more);
        self.send(
            signer,
            escrow(signer.id),
            &actors,
            fresh,
            instruction,
            timestamp,
        )
    }

    /// Has the controller send `instruction` to `party`'s escrow actor, with `seeds` authorizing
    /// its own PDAs. `signer` signs the call to the controller, and its signature carries.
    #[allow(clippy::too_many_arguments)]
    fn relay(
        &mut self,
        signer: &Party,
        party: AccountId,
        seeds: Vec<[u8; 32]>,
        instruction: &Instruction,
        more: &[Actor],
        fresh: Vec<PublicAccountEvidence>,
        timestamp: u64,
    ) -> Result<(), LeeError> {
        let root = Actor::new(signer.id, CONTROLLER);
        // The job is the buyer's; a treasury buying for itself has its own.
        let mut actors = vec![root, escrow(party), escrow(job())];
        if job_for(party) != job() && party != provider().id {
            actors.push(escrow(job_for(party)));
        }
        actors.extend_from_slice(more);
        let message = (
            PROGRAM,
            party,
            seeds,
            borsh::to_vec(instruction).expect("instruction serializes"),
        );
        self.send(signer, root, &actors, fresh, &message, timestamp)
    }

    fn balance(&self, account_id: AccountId) -> Balance {
        self.state
            .get_account_by_id(account_id)
            .data
            .native_balance()
            .expect("canonical balance")
    }

    fn job(&self) -> Job {
        self.job_at(job())
    }

    fn job_at(&self, job: AccountId) -> Job {
        let account = self.state.get_account_by_id(job);
        borsh::from_slice(account.data.actor_state(PROGRAM)).expect("job record decodes")
    }

    fn open(&mut self) -> Result<(), LeeError> {
        self.open_controlled_by(None)
    }

    fn open_controlled_by(&mut self, controller: Option<AccountId>) -> Result<(), LeeError> {
        self.call(
            &buyer(),
            &open_instruction(controller),
            &[native(buyer().id), native(job())],
            BEFORE,
        )
    }

    fn deliver(&mut self, timestamp: u64) -> Result<(), LeeError> {
        let deliver = Instruction::Deliver {
            buyer: buyer().id,
            job_ref: JOB_REF,
            result: RESULT,
            deadline: DEADLINE,
        };
        self.call(&provider(), &deliver, &[], timestamp)
    }

    fn refund(&mut self, amount: Balance, deadline: u64, timestamp: u64) -> Result<(), LeeError> {
        let refund = Instruction::Refund {
            job_ref: JOB_REF,
            amount,
            deadline,
        };
        self.call_admitting(
            &buyer(),
            &refund,
            &[native(job()), native(refund_to().id)],
            vec![evidence(&refund_to())],
            timestamp,
        )
    }

    fn claim_of(&mut self, amount: Balance) -> Result<(), LeeError> {
        let claim = Instruction::Claim {
            buyer: buyer().id,
            job_ref: JOB_REF,
            amount,
        };
        self.call_admitting(
            &provider(),
            &claim,
            &[native(job()), native(pay_to().id)],
            vec![evidence(&pay_to())],
            BEFORE,
        )
    }
}

const RESULT: [u8; 32] = [4; 32];

/// The job of `buyer` with this test's job reference.
fn job_for(buyer: AccountId) -> AccountId {
    job_account_id(&PROGRAM, &buyer, &JOB_REF)
}

fn open_instruction(controller: Option<AccountId>) -> Instruction {
    Instruction::Open {
        job_ref: JOB_REF,
        provider: provider().id,
        pay_to: pay_to().id,
        refund_to: refund_to().id,
        amount: AMOUNT,
        deadline: DEADLINE,
        controller,
    }
}

fn give_back() -> Instruction {
    Instruction::Return {
        buyer: buyer().id,
        job_ref: JOB_REF,
    }
}

/// Whether `result` is a program exiting with `code`, as the README's error table numbers it.
fn refused(result: &Result<(), LeeError>, code: u32) -> bool {
    matches!(result, Err(LeeError::ProgramExitedWithCode { code: exited, .. }) if *exited == code)
}

fn release_of(amount: Balance) -> Instruction {
    Instruction::Release {
        job_ref: JOB_REF,
        amount,
    }
}

#[test]
fn open_locks_the_buyers_lepta_and_a_claim_pays_the_pay_to() {
    let mut chain = Chain::new();

    chain.open().expect("open");
    assert_eq!(chain.balance(buyer().id), START - AMOUNT);
    assert_eq!(chain.balance(job()), AMOUNT);
    assert_eq!(chain.job().state, JobState::Open);

    chain
        .call(&buyer(), &release_of(200), &[], BEFORE)
        .expect("release part");
    chain.claim_of(200).expect("claim the released part");
    assert_eq!(chain.balance(pay_to().id), 200);
    assert_eq!(chain.balance(job()), AMOUNT - 200);
    assert_eq!(chain.job().claimed, 200);
}

#[test]
fn open_deliver_claim_pays_the_providers_pay_to() {
    let mut chain = Chain::new();
    chain.open().expect("open");
    chain.deliver(BEFORE).expect("deliver");
    assert_eq!(chain.job().state, JobState::Delivered);
    assert_eq!(chain.job().result, Some(RESULT));
    chain.claim_of(AMOUNT).expect("claim");
    assert_eq!(chain.job().claimed, AMOUNT);
    assert_eq!(chain.balance(job()), 0);
    assert_eq!(chain.balance(pay_to().id), AMOUNT);
    assert_eq!(chain.balance(provider().id), START);
    assert_eq!(chain.balance(buyer().id), START - AMOUNT);
}

#[test]
fn an_undelivered_job_refunds_the_buyer_only_from_the_deadline() {
    let mut chain = Chain::new();
    chain.open().expect("open");
    assert!(matches!(
        chain.refund(AMOUNT, DEADLINE, BEFORE),
        Err(LeeError::OutOfValidityWindow)
    ));
    assert_eq!(chain.balance(job()), AMOUNT);
    chain
        .refund(AMOUNT, DEADLINE, DEADLINE)
        .expect("refund at the deadline");
    assert_eq!(chain.job().state, JobState::Refunded);
    assert_eq!(chain.balance(job()), 0);
    assert_eq!(chain.balance(refund_to().id), AMOUNT);
}

#[test]
fn a_late_delivery_is_refused_and_the_buyer_can_refund() {
    let mut chain = Chain::new();
    chain.open().expect("open");
    assert!(matches!(
        chain.deliver(DEADLINE),
        Err(LeeError::OutOfValidityWindow)
    ));
    chain.refund(AMOUNT, DEADLINE, DEADLINE).expect("refund");
    assert_eq!(chain.balance(refund_to().id), AMOUNT);
}

#[test]
fn opening_after_the_deadline_is_refused() {
    let mut chain = Chain::new();
    let late = chain.call(
        &buyer(),
        &open_instruction(None),
        &[native(buyer().id), native(job())],
        DEADLINE,
    );
    assert!(matches!(late, Err(LeeError::OutOfValidityWindow)));
    assert_eq!(chain.balance(buyer().id), START);
}

#[test]
fn released_parts_are_claimed_and_the_rest_refunded_after_the_deadline() {
    let mut chain = Chain::new();
    chain.open().expect("open");
    chain
        .call(&buyer(), &release_of(200), &[], BEFORE)
        .expect("release part");
    chain.claim_of(200).expect("claim the released part");
    chain
        .refund(AMOUNT - 200, DEADLINE, DEADLINE)
        .expect("refund the rest");
    assert_eq!(chain.job().state, JobState::Refunded);
    assert_eq!(chain.balance(pay_to().id), 200);
    assert_eq!(chain.balance(refund_to().id), AMOUNT - 200);
    assert_eq!(chain.balance(job()), 0);
}

#[test]
fn a_refused_call_exits_with_its_code_and_moves_nothing() {
    let mut chain = Chain::new();
    chain.open().expect("open");
    // Claiming before anything is released.
    let early = chain.claim_of(AMOUNT);
    assert!(refused(&early, 10), "{early:?}");
    assert_eq!(chain.balance(job()), AMOUNT);
    assert_eq!(chain.job().claimed, 0);
}

#[test]
fn nobody_can_move_the_deposit_without_the_escrow_program() {
    let mut chain = Chain::new();
    chain.open().expect("open");
    // The buyer signs a plain native transfer out of the job account.
    let drain = chain.send(
        &buyer(),
        native(job()),
        &[native(job()), native(buyer().id)],
        Vec::new(),
        &NativeMessage::Transfer {
            to: buyer().id,
            amount: AMOUNT,
        },
        BEFORE,
    );
    assert!(
        matches!(
            &drain,
            Err(LeeError::InvalidProgramBehavior(
                InvalidProgramBehaviorError::NativeTransferFailed(
                    TransferError::UnauthorizedSender { account_id }
                )
            )) if *account_id == job()
        ),
        "{drain:?}"
    );
    assert_eq!(chain.balance(job()), AMOUNT);
}

#[test]
fn a_returned_job_is_refunded_before_the_deadline() {
    let mut chain = Chain::new();
    chain.open().expect("open");
    chain
        .call(&provider(), &give_back(), &[], BEFORE)
        .expect("return");
    assert_eq!(chain.job().state, JobState::Returned);
    chain
        .refund(AMOUNT, 0, BEFORE)
        .expect("refund before the deadline");
    assert_eq!(chain.job().state, JobState::Refunded);
    assert_eq!(chain.balance(refund_to().id), AMOUNT);
    assert_eq!(chain.balance(provider().id), START);
}

#[test]
fn a_controller_releases_part_and_returns_the_rest_without_the_parties() {
    let mut chain = Chain::new();
    chain.open_controlled_by(Some(CONTROLLER)).expect("open");
    // On a controlled job, delivering releases nothing: the controller judges it.
    chain.deliver(BEFORE).expect("deliver");
    assert_eq!(chain.job().released, 0);
    assert!(refused(&chain.claim_of(AMOUNT), 10));
    chain
        .relay(
            &operator(),
            buyer().id,
            vec![],
            &release_of(200),
            &[],
            vec![],
            BEFORE,
        )
        .expect("the controller releases part");
    chain
        .relay(
            &operator(),
            provider().id,
            vec![],
            &give_back(),
            &[],
            vec![],
            BEFORE,
        )
        .expect("the controller returns the rest");
    assert_eq!(chain.job().state, JobState::Returned);
    chain.claim_of(200).expect("the provider claims its part");
    chain
        .refund(AMOUNT - 200, 0, BEFORE)
        .expect("the buyer refunds the rest");
    assert_eq!(chain.balance(pay_to().id), 200);
    assert_eq!(chain.balance(refund_to().id), AMOUNT - 200);
    assert_eq!(chain.balance(job()), 0);
}

#[test]
fn a_program_cannot_act_on_a_job_it_does_not_control_even_when_the_buyer_signs() {
    let mut chain = Chain::new();
    chain.open().expect("open");
    // The buyer signs a call to some program, and LEZ carries that signature into the
    // program's call to the escrow.
    let calls = [
        (release_of(AMOUNT), vec![]),
        (
            Instruction::Refund {
                job_ref: JOB_REF,
                amount: AMOUNT,
                deadline: 0,
            },
            vec![native(job()), native(refund_to().id)],
        ),
    ];
    for (instruction, more) in calls {
        let result = chain.relay(
            &buyer(),
            buyer().id,
            vec![],
            &instruction,
            &more,
            vec![evidence(&refund_to())],
            BEFORE,
        );
        assert!(refused(&result, 11), "{instruction:?}: {result:?}");
    }
    assert_eq!(chain.job().released, 0);
    assert_eq!(chain.balance(job()), AMOUNT);
}

#[test]
fn a_program_opens_a_job_only_for_itself_and_cannot_claim_for_the_provider() {
    let mut chain = Chain::new();
    // The buyer signs, but the controller names no controller, or another program.
    for named in [None, Some(PROGRAM)] {
        let result = chain.relay(
            &buyer(),
            buyer().id,
            vec![],
            &open_instruction(named),
            &[native(buyer().id), native(job())],
            vec![],
            BEFORE,
        );
        assert!(refused(&result, 11), "{named:?}: {result:?}");
    }
    assert_eq!(chain.balance(buyer().id), START);

    chain.open_controlled_by(Some(CONTROLLER)).expect("open");
    chain
        .relay(
            &operator(),
            buyer().id,
            vec![],
            &release_of(AMOUNT),
            &[],
            vec![],
            BEFORE,
        )
        .expect("the controller releases everything");
    let claim = Instruction::Claim {
        buyer: buyer().id,
        job_ref: JOB_REF,
        amount: AMOUNT,
    };
    let result = chain.relay(
        &operator(),
        provider().id,
        vec![],
        &claim,
        &[native(job()), native(pay_to().id)],
        vec![evidence(&pay_to())],
        BEFORE,
    );
    assert!(refused(&result, 2), "{result:?}");
    assert_eq!(chain.balance(job()), AMOUNT);
}

#[test]
fn a_controllers_own_account_opens_and_refunds_a_job_through_it() {
    let mut chain = Chain::new();
    let seed = [0x5E; 32];
    let treasury = AccountId::for_public_pda(&CONTROLLER, &PdaSeed::new(seed));
    let job = job_for(treasury);
    chain
        .send(
            &buyer(),
            native(buyer().id),
            &[native(buyer().id), native(treasury)],
            vec![PublicAccountEvidence::Pda {
                program: CONTROLLER,
                seed: PdaSeed::new(seed),
            }],
            &NativeMessage::Transfer {
                to: treasury,
                amount: AMOUNT,
            },
            BEFORE,
        )
        .expect("fund the treasury");

    let open = Instruction::Open {
        job_ref: JOB_REF,
        provider: provider().id,
        pay_to: pay_to().id,
        refund_to: refund_to().id,
        amount: AMOUNT,
        deadline: DEADLINE,
        controller: Some(CONTROLLER),
    };
    chain
        .relay(
            &operator(),
            treasury,
            vec![seed],
            &open,
            &[native(treasury), native(job)],
            vec![],
            BEFORE,
        )
        .expect("the treasury opens a job through the controller");
    assert_eq!(chain.balance(treasury), 0);
    assert_eq!(chain.balance(job), AMOUNT);
    assert_eq!(chain.job_at(job).controller, Some(CONTROLLER));

    let refund = Instruction::Refund {
        job_ref: JOB_REF,
        amount: AMOUNT,
        deadline: DEADLINE,
    };
    let payout = [native(job), native(refund_to().id)];
    // Without the seed the treasury hasn't authorized the refund.
    let unseeded = chain.relay(
        &operator(),
        treasury,
        vec![],
        &refund,
        &payout,
        vec![evidence(&refund_to())],
        DEADLINE,
    );
    assert!(refused(&unseeded, 2), "{unseeded:?}");
    chain
        .relay(
            &operator(),
            treasury,
            vec![seed],
            &refund,
            &payout,
            vec![evidence(&refund_to())],
            DEADLINE,
        )
        .expect("the treasury refunds through the controller");
    assert_eq!(chain.balance(refund_to().id), AMOUNT);
    assert_eq!(chain.balance(job), 0);
}

fn case() -> AccountId {
    case_account_id(&ARBITER, &job())
}

/// One call to the example arbiter from `signer`'s own actor, declaring the case, the job and
/// `more`.
fn arbiter(
    chain: &mut Chain,
    signer: &Party,
    instruction: &ArbiterInstruction,
    more: &[Actor],
) -> Result<(), LeeError> {
    let root = Actor::new(signer.id, ARBITER);
    let mut actors = vec![root, Actor::new(case(), ARBITER), escrow(job())];
    actors.extend_from_slice(more);
    chain.send(signer, root, &actors, Vec::new(), instruction, BEFORE)
}

/// The buyer opens a job through the example arbiter, which records the operator as its judge.
fn open_with_judge(chain: &mut Chain) {
    let open = ArbiterInstruction::Open {
        escrow: PROGRAM,
        judge: operator().id,
        job_ref: JOB_REF,
        provider: provider().id,
        pay_to: pay_to().id,
        refund_to: refund_to().id,
        amount: AMOUNT,
        deadline: DEADLINE,
    };
    arbiter(
        chain,
        &buyer(),
        &open,
        &[escrow(buyer().id), native(buyer().id), native(job())],
    )
    .expect("open through the arbiter");
}

fn decide(decision: Decision) -> ArbiterInstruction {
    ArbiterInstruction::Decide {
        escrow: PROGRAM,
        buyer: buyer().id,
        job_ref: JOB_REF,
        decision,
    }
}

#[test]
fn the_arbiters_judge_pays_part_and_returns_the_rest() {
    let mut chain = Chain::new();
    open_with_judge(&mut chain);
    assert_eq!(chain.job().controller, Some(ARBITER));
    assert_eq!(chain.balance(job()), AMOUNT);

    arbiter(
        &mut chain,
        &operator(),
        &decide(Decision::Release { amount: 200 }),
        &[escrow(buyer().id)],
    )
    .expect("the judge releases part");
    arbiter(
        &mut chain,
        &operator(),
        &decide(Decision::Return),
        &[escrow(provider().id)],
    )
    .expect("the judge returns the rest");
    assert_eq!(chain.job().state, JobState::Returned);

    chain.claim_of(200).expect("the provider claims its part");
    chain
        .refund(AMOUNT - 200, 0, BEFORE)
        .expect("the buyer refunds the rest");
    assert_eq!(chain.balance(pay_to().id), 200);
    assert_eq!(chain.balance(refund_to().id), AMOUNT - 200);
}

#[test]
fn only_the_cases_judge_decides() {
    let mut chain = Chain::new();
    open_with_judge(&mut chain);
    // The provider signs a decision in its own favour.
    let result = arbiter(
        &mut chain,
        &provider(),
        &decide(Decision::Release { amount: AMOUNT }),
        &[escrow(buyer().id)],
    );
    assert!(refused(&result, 105), "{result:?}");
    assert_eq!(chain.job().released, 0);
}

#[test]
fn a_message_that_does_not_decode_exits_with_code_1() {
    let mut chain = Chain::new();
    let garbage = chain.send(
        &buyer(),
        escrow(buyer().id),
        &[escrow(buyer().id)],
        Vec::new(),
        &[0xff_u8],
        BEFORE,
    );
    assert!(refused(&garbage, 1), "{garbage:?}");
}

#[test]
fn a_message_straight_to_a_jobs_actor_cannot_touch_the_job() {
    let mut chain = Chain::new();
    chain.open().expect("open");
    // Sent to the job's actor, an instruction is the job account acting as a party: here as a
    // buyer, naming a job of its own that doesn't exist.
    let result = chain.send(
        &buyer(),
        escrow(job()),
        &[escrow(job()), escrow(job_for(job()))],
        Vec::new(),
        &release_of(AMOUNT),
        BEFORE,
    );
    assert!(refused(&result, 8), "{result:?}");
    assert_eq!(chain.job().released, 0);
}

#[test]
fn a_controller_cannot_open_a_job_for_a_buyer_who_did_not_sign() {
    let mut chain = Chain::new();
    let result = chain.relay(
        &operator(),
        buyer().id,
        vec![],
        &open_instruction(Some(CONTROLLER)),
        &[native(buyer().id), native(job())],
        vec![],
        BEFORE,
    );
    assert!(refused(&result, 2), "{result:?}");
    assert_eq!(chain.balance(buyer().id), START);
}

#[test]
fn a_judge_decides_only_by_a_direct_call() {
    let mut chain = Chain::new();
    open_with_judge(&mut chain);
    // The judge signs a call to some program, which relays a decision to the arbiter.
    let relayed = (
        ARBITER,
        operator().id,
        Vec::<[u8; 32]>::new(),
        borsh::to_vec(&decide(Decision::Release { amount: AMOUNT })).expect("serializes"),
    );
    let root = Actor::new(operator().id, CONTROLLER);
    let result = chain.send(
        &operator(),
        root,
        &[
            root,
            Actor::new(operator().id, ARBITER),
            Actor::new(case(), ARBITER),
            escrow(buyer().id),
            escrow(job()),
        ],
        Vec::new(),
        &relayed,
        BEFORE,
    );
    assert!(refused(&result, 108), "{result:?}");
    assert_eq!(chain.job().released, 0);
}
