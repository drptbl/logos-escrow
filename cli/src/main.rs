//! Calls the escrow program on a LEZ v0.4 sequencer from a LEZ wallet (`LEE_WALLET_HOME_DIR`).
//!
//! A party sends each instruction to its own actor under the escrow, declaring the job's actor
//! and, for a call that moves lepta, both ends' native balances. A call goes public through
//! `WalletCore::send_pub_tx_paid_by`, or private through `WalletCore::send_tx` when the signer or
//! the payee is one of the wallet's private accounts. The job record is read back from the job
//! account's escrow state.

use std::{
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context as _, Result, bail};
use clap::{Parser, Subcommand};
use lee::{privacy_preserving_transaction::circuit::ProgramCatalog, program::Program};
use lee_core::account::{AccountId, Balance};
use logos_escrow_core::{Hash32, Instruction, Job, JobState, job_account_id};
use wallet::{AccountIdentity, AccountMention, AsyncDelivery, WalletCore, WalletSequencerClient};

#[derive(Parser)]
#[command(about = "Drive the logos-escrow program from a LEZ v0.4 wallet")]
struct Args {
    /// The escrow program's header account id (base58). logos-devnet exports it.
    #[arg(long, env = "LOGOS_PROGRAM_ESCROW", global = true)]
    program: Option<AccountId>,
    /// Send the call even when the job record says it will be refused, which a public call
    /// still pays for.
    #[arg(long, global = true)]
    force: bool,
    /// A wallet account that pays the transaction's fee; by default the signer pays. A private
    /// call pays its fee in the proof, from one of the wallet's private accounts.
    #[arg(long, global = true)]
    payer: Option<AccountId>,
    /// The escrow guest binary, which a private call proves locally.
    #[arg(
        long,
        env = "LOGOS_ESCROW_ELF",
        global = true,
        default_value = "methods/guest/target/riscv32im-risc0-zkvm-elf/docker/logos_escrow.bin"
    )]
    elf: PathBuf,
    #[command(subcommand)]
    command: Command,
}

/// Names one job: the buyer and the job reference (64 hex characters).
#[derive(clap::Args)]
struct JobArgs {
    #[arg(long)]
    buyer: AccountId,
    #[arg(long, value_parser = parse_hash)]
    job_ref: Hash32,
}

/// A payout from a job, to the payout address the job's record names.
#[derive(clap::Args)]
struct PayoutArgs {
    #[command(flatten)]
    job: JobArgs,
    /// Pay a public account this wallet holds no key for, which has to exist on chain already.
    /// Without it, the CLI refuses to send a payout it can't place, because a private address
    /// paid publicly is burned.
    #[arg(long)]
    public_payee: bool,
}

#[derive(Subcommand)]
enum Command {
    /// Print the job account for a buyer and job reference.
    JobAccount(JobArgs),
    /// Print a job's record and the balance it holds.
    Show(JobArgs),
    /// Make a fresh private payout address: a new private account in this wallet. Prints its id,
    /// to give as `--pay-to` or `--refund-to`.
    PayoutAddress,
    /// Buyer: lock `amount` for `provider` until `deadline_ms` (or `in_secs` from now).
    Open {
        #[command(flatten)]
        job: JobArgs,
        #[arg(long)]
        provider: AccountId,
        /// Where the provider is paid.
        #[arg(long)]
        pay_to: AccountId,
        /// Where the buyer gets the deposit back.
        #[arg(long)]
        refund_to: AccountId,
        #[arg(long)]
        amount: Balance,
        #[arg(long, conflicts_with = "in_secs")]
        deadline_ms: Option<u64>,
        #[arg(long)]
        in_secs: Option<u64>,
        /// A program that may release and return the job besides the parties. On a controlled
        /// job, delivering releases nothing; the controller decides.
        #[arg(long)]
        controller: Option<AccountId>,
    },
    /// Provider: record the result hash before the deadline.
    Deliver {
        #[command(flatten)]
        job: JobArgs,
        #[arg(long, value_parser = parse_hash)]
        result: Hash32,
    },
    /// Provider: collect everything released and not yet claimed to the job's `pay_to`.
    Claim(PayoutArgs),
    /// Buyer: let the provider claim `amount` more, by default all that is left.
    Release {
        #[command(flatten)]
        job: JobArgs,
        #[arg(long)]
        amount: Option<Balance>,
    },
    /// Buyer: take back what was never released to the job's `refund_to`, after its deadline or
    /// once the provider returned it.
    Refund(PayoutArgs),
    /// Provider: give an open job up, so the buyer can refund what was never released at once.
    Return(JobArgs),
}

fn parse_hash(text: &str) -> Result<Hash32> {
    let bytes = hex::decode(text).context("not hex")?;
    <Hash32>::try_from(bytes).map_err(|_| anyhow::anyhow!("expected 32 bytes"))
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let force = args.force;
    let wallet = WalletCore::from_env().context("open the wallet at LEE_WALLET_HOME_DIR")?;
    let mut escrow = Escrow {
        wallet,
        program: args
            .program
            .context("set --program or LOGOS_PROGRAM_ESCROW to the escrow's program id")?,
        payer: args.payer,
        elf: args.elf,
    };

    match args.command {
        Command::JobAccount(job) => println!("{}", escrow.job_account(&job)),
        Command::Show(job) => escrow.show(&job).await?,
        Command::PayoutAddress => {
            let (account_id, _) = escrow.wallet.create_new_account_private(None);
            escrow.wallet.store_persistent_data()?;
            println!("{account_id}");
        }
        Command::Open {
            job,
            provider,
            pay_to,
            refund_to,
            amount,
            deadline_ms,
            in_secs,
            controller,
        } => {
            let deadline = match (deadline_ms, in_secs) {
                (Some(deadline), _) => deadline,
                (None, Some(secs)) => secs
                    .checked_mul(1000)
                    .and_then(|ms| ms.checked_add(now_ms().ok()?))
                    .context("deadline overflows")?,
                (None, None) => bail!("set --deadline-ms or --in-secs"),
            };
            let instruction = Instruction::Open {
                job_ref: job.job_ref,
                provider,
                pay_to,
                refund_to,
                amount,
                deadline,
                controller,
            };
            let job_account = escrow.job_account(&job);
            let exists = escrow.record(&job).await.is_ok();
            check(
                force,
                open_preflight(&instruction, job.buyer, job_account, exists, now_ms()?),
            )?;
            let buyer = escrow.signer(job.buyer);
            let accounts = vec![
                buyer.clone().select_program_actor_state(escrow.program),
                escrow.job(&job),
                buyer.balance(),
                AccountIdentity::PublicNoSign(job_account).balance(),
            ];
            escrow.send(&job, accounts, &instruction).await?;
        }
        Command::Deliver { job, result } => {
            let record = escrow.record(&job).await?;
            check(force, preflight(&Call::Deliver, &record, now_ms()?))?;
            let instruction = Instruction::Deliver {
                buyer: job.buyer,
                job_ref: job.job_ref,
                result,
                deadline: record.deadline,
            };
            let accounts = vec![escrow.party(record.provider), escrow.job(&job)];
            escrow.send(&job, accounts, &instruction).await?;
        }
        Command::Claim(payout) => {
            // Sync first, so a payout address someone already paid into is up to date.
            escrow.wallet.sync_to_latest_block().await?;
            let record = escrow.record(&payout.job).await?;
            check(force, preflight(&Call::Claim, &record, now_ms()?))?;
            let instruction = Instruction::Claim {
                buyer: payout.job.buyer,
                job_ref: payout.job.job_ref,
                amount: record.claimable(),
            };
            let accounts = escrow.payout_accounts(&payout, record.provider, record.pay_to)?;
            escrow.send(&payout.job, accounts, &instruction).await?;
        }
        Command::Release { job, amount } => {
            let record = escrow.record(&job).await?;
            let amount = amount.unwrap_or_else(|| record.unreleased());
            check(force, preflight(&Call::Release(amount), &record, now_ms()?))?;
            let instruction = Instruction::Release {
                job_ref: job.job_ref,
                amount,
            };
            let accounts = vec![escrow.party(job.buyer), escrow.job(&job)];
            escrow.send(&job, accounts, &instruction).await?;
        }
        Command::Refund(payout) => {
            escrow.wallet.sync_to_latest_block().await?;
            let record = escrow.record(&payout.job).await?;
            check(force, preflight(&Call::Refund, &record, now_ms()?))?;
            let instruction = Instruction::Refund {
                job_ref: payout.job.job_ref,
                amount: record.unreleased(),
                // A returned job refunds at once, so its deadline no longer applies.
                deadline: if record.state == JobState::Returned {
                    0
                } else {
                    record.deadline
                },
            };
            let accounts = escrow.payout_accounts(&payout, payout.job.buyer, record.refund_to)?;
            escrow.send(&payout.job, accounts, &instruction).await?;
        }
        Command::Return(job) => {
            let record = escrow.record(&job).await?;
            check(force, preflight(&Call::Return, &record, now_ms()?))?;
            let instruction = Instruction::Return {
                buyer: job.buyer,
                job_ref: job.job_ref,
            };
            let accounts = vec![escrow.party(record.provider), escrow.job(&job)];
            escrow.send(&job, accounts, &instruction).await?;
        }
    }
    Ok(())
}

/// A call the CLI is about to send, to check against the job record first.
#[derive(Debug)]
enum Call {
    Deliver,
    Claim,
    Release(Balance),
    Refund,
    Return,
}

/// Why the escrow, or LEZ's deadline window, would refuse `call` on `record` at `now` (in
/// milliseconds). A refused public call is still included and charged, so the CLI checks before
/// it sends. The clock is this machine's, which can differ a little from the block's.
fn preflight(call: &Call, record: &Job, now: u64) -> Result<(), String> {
    let open = record.state == JobState::Open;
    match call {
        Call::Deliver if !open || record.result.is_some() => Err(format!(
            "the job can't be delivered: it is {:?}{}",
            record.state,
            if record.result.is_some() {
                ", with a result already"
            } else {
                ""
            }
        )),
        Call::Deliver if now >= record.deadline => {
            Err("the deadline has passed, so LEZ would refuse the call".into())
        }
        Call::Claim if record.claimable() == 0 => Err("nothing is released and unclaimed".into()),
        Call::Release(_) if !open => Err(format!(
            "only an open job can be released: it is {:?}",
            record.state
        )),
        Call::Release(amount) if *amount == 0 || *amount > record.unreleased() => {
            Err(format!("{} lepta are left to release", record.unreleased()))
        }
        Call::Refund if !matches!(record.state, JobState::Open | JobState::Returned) => Err(
            format!("the job can't be refunded: it is {:?}", record.state),
        ),
        Call::Refund if open && now < record.deadline => {
            Err("the deadline hasn't passed, so LEZ would refuse the call".into())
        }
        Call::Refund if record.unreleased() == 0 => Err("nothing is left to refund".into()),
        Call::Return if !open => Err(format!(
            "only an open job can be returned: it is {:?}",
            record.state
        )),
        Call::Return if record.unreleased() == 0 => {
            Err("everything is released, so nothing is left to return".into())
        }
        _ => Ok(()),
    }
}

/// Why the escrow, or LEZ's deadline window, would refuse `open` for `buyer` at `now`, with
/// `exists` saying whether `job` already holds a job. The terms check is the one `Open` makes
/// in `core`.
fn open_preflight(
    open: &Instruction,
    buyer: AccountId,
    job: AccountId,
    exists: bool,
    now: u64,
) -> Result<(), String> {
    let Instruction::Open {
        provider,
        pay_to,
        refund_to,
        amount,
        deadline,
        ..
    } = open
    else {
        return Err("not an Open".into());
    };
    if exists {
        return Err("this job reference is used: the job account already holds a job".into());
    }
    if *amount == 0 {
        return Err("the amount is zero".into());
    }
    if *provider == buyer {
        return Err("the buyer can't be its own provider".into());
    }
    if *pay_to == job || *refund_to == job {
        return Err("the job account can't be a payout address".into());
    }
    if now >= *deadline {
        return Err("the deadline has passed, so LEZ would refuse the call".into());
    }
    Ok(())
}

/// Stops before a call that would be refused, unless `--force`.
fn check(force: bool, verdict: Result<(), String>) -> Result<()> {
    match verdict {
        Err(why) if !force => bail!("not sent: {why} (pass --force to send it anyway)"),
        _ => Ok(()),
    }
}

fn now_ms() -> Result<u64> {
    Ok(u64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
    )?)
}

struct Escrow<C: WalletSequencerClient> {
    wallet: WalletCore<C>,
    program: AccountId,
    payer: Option<AccountId>,
    elf: PathBuf,
}

impl<C: WalletSequencerClient> Escrow<C> {
    fn job_account(&self, job: &JobArgs) -> AccountId {
        job_account_id(&self.program, &job.buyer, &job.job_ref)
    }

    /// A signer: one of the wallet's private accounts if it holds one with this id, otherwise a
    /// public account.
    fn signer(&self, account_id: AccountId) -> AccountIdentity {
        if self.is_private(account_id) {
            AccountIdentity::PrivateOwned(account_id)
        } else {
            AccountIdentity::Public(account_id)
        }
    }

    fn is_private(&self, account_id: AccountId) -> bool {
        self.wallet
            .storage()
            .key_chain()
            .private_account(account_id)
            .is_some()
    }

    /// The party's own actor under the escrow, where it sends its instruction.
    fn party(&self, account_id: AccountId) -> AccountMention {
        self.signer(account_id)
            .select_program_actor_state(self.program)
    }

    /// The job's actor under the escrow, which holds its record.
    fn job(&self, job: &JobArgs) -> AccountMention {
        AccountIdentity::PublicNoSign(self.job_account(job))
            .select_program_actor_state(self.program)
    }

    /// The signer's actor, the job's, and both native balances a payout moves between.
    fn payout_accounts(
        &self,
        payout: &PayoutArgs,
        signer: AccountId,
        payee: AccountId,
    ) -> Result<Vec<AccountMention>> {
        let mut accounts = vec![self.party(signer), self.job(&payout.job)];
        accounts.push(AccountIdentity::PublicNoSign(self.job_account(&payout.job)).balance());
        // The wallet names one account by one identity in a transaction, so a signer paid to
        // itself keeps its signer's.
        accounts.push(if payee == signer {
            self.signer(signer).balance()
        } else {
            self.payee(payee, payout)?
        });
        Ok(accounts)
    }

    /// The payout address's native balance, as the account kind the wallet can pay into: one of
    /// its own private accounts, or a public account. LEZ admits a public account the chain has
    /// never seen only with its key, which the wallet adds for the accounts it holds.
    fn payee(&self, payee: AccountId, payout: &PayoutArgs) -> Result<AccountMention> {
        let key_chain = self.wallet.storage().key_chain();
        if self.is_private(payee) {
            Ok(AccountIdentity::PrivateOwned(payee).balance().receiving())
        } else if payout.public_payee || key_chain.pub_account_signing_key(payee).is_some() {
            Ok(AccountIdentity::PublicNoSign(payee).balance())
        } else {
            bail!(
                "can't tell what kind of account {payee} is: pull a payout from the wallet that \
                 holds it, or pass --public-payee for a public account already on chain"
            )
        }
    }

    async fn record(&self, job: &JobArgs) -> Result<Job> {
        let account = self
            .wallet
            .get_account_public(self.job_account(job))
            .await?
            .unwrap_or_default();
        let state = account.data.actor_state(self.program);
        if state.is_empty() {
            bail!("no job at {}", self.job_account(job));
        }
        Ok(borsh::from_slice(state)?)
    }

    async fn show(&self, job: &JobArgs) -> Result<()> {
        let job_account = self.job_account(job);
        let balance = self.wallet.get_account_balance(job_account).await?;
        println!("job account: {job_account}");
        println!("holds:       {balance} lepta");
        match self.record(job).await {
            Ok(record) => println!("record:      {record:?}"),
            Err(error) => println!("record:      none ({error})"),
        }
        Ok(())
    }

    async fn send(
        &mut self,
        job: &JobArgs,
        accounts: Vec<AccountMention>,
        instruction: &Instruction,
    ) -> Result<()> {
        let data = borsh::to_vec(instruction)?;
        println!("instruction: {}", hex::encode(&data));
        let private = accounts.iter().any(|mention| mention.identity.is_private());
        let hash = if private {
            // The wallet proves against the private accounts' latest notes.
            self.wallet.sync_to_latest_block().await?;
            let elf = std::fs::read(&self.elf)
                .with_context(|| format!("read the escrow binary at {}", self.elf.display()))?;
            let programs = ProgramCatalog::from([(self.program, Program::new(elf.into())?)]);
            println!("proving locally...");
            let (hash, _) = self
                .wallet
                .send_tx_with_pre_check(
                    accounts,
                    0,
                    data,
                    &programs,
                    None,
                    AsyncDelivery::default(),
                    self.payer,
                    |_| Ok(()),
                )
                .await
                .map_err(|error| anyhow::anyhow!("send failed: {error:?}"))?;
            hash
        } else {
            self.wallet
                .send_pub_tx_paid_by(accounts, 0, data, self.payer)
                .await
                .map_err(|error| anyhow::anyhow!("send failed: {error:?}"))?
        };
        println!("tx:          {hash}");
        let (_, block) = self
            .wallet
            .poll_transaction(hash)
            .await
            .context("transaction not included")?;
        println!("block:       {block}");
        if private {
            self.wallet.sync_to_latest_block().await?;
            self.wallet.store_persistent_data()?;
        }
        // A public call that was refused is still included and charged, so read the record back.
        self.show(job).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEADLINE: u64 = 1_800_000_000_000;

    fn record(state: JobState, released: Balance, claimed: Balance) -> Job {
        Job {
            buyer: AccountId::new([1; 32]),
            provider: AccountId::new([2; 32]),
            pay_to: AccountId::new([2; 32]),
            refund_to: AccountId::new([1; 32]),
            amount: 500,
            released,
            claimed,
            deadline: DEADLINE,
            state,
            result: None,
            controller: None,
        }
    }

    #[test]
    fn calls_the_record_allows_pass_the_preflight() {
        let open = record(JobState::Open, 200, 0);
        assert_eq!(preflight(&Call::Deliver, &open, DEADLINE - 1), Ok(()));
        assert_eq!(preflight(&Call::Claim, &open, DEADLINE + 1), Ok(()));
        assert_eq!(preflight(&Call::Release(300), &open, DEADLINE + 1), Ok(()));
        assert_eq!(preflight(&Call::Refund, &open, DEADLINE), Ok(()));
        assert_eq!(preflight(&Call::Return, &open, DEADLINE + 1), Ok(()));
        let returned = record(JobState::Returned, 0, 0);
        assert_eq!(preflight(&Call::Refund, &returned, DEADLINE - 1), Ok(()));
    }

    #[test]
    fn a_call_outside_the_deadline_window_is_refused_before_it_costs_the_gas_limit() {
        let open = record(JobState::Open, 0, 0);
        assert!(preflight(&Call::Deliver, &open, DEADLINE).is_err());
        assert!(preflight(&Call::Refund, &open, DEADLINE - 1).is_err());
        assert!(open_preflight(&open_terms(500), BUYER, JOB, false, DEADLINE).is_err());
        assert_eq!(
            open_preflight(&open_terms(500), BUYER, JOB, false, DEADLINE - 1),
            Ok(())
        );
    }

    const BUYER: AccountId = AccountId::new([1; 32]);
    const PROVIDER: AccountId = AccountId::new([2; 32]);
    const JOB: AccountId = AccountId::new([7; 32]);

    fn open_terms(amount: Balance) -> Instruction {
        Instruction::Open {
            job_ref: [9; 32],
            provider: PROVIDER,
            pay_to: PROVIDER,
            refund_to: BUYER,
            amount,
            deadline: DEADLINE,
            controller: None,
        }
    }

    #[test]
    fn an_open_on_a_used_job_ref_is_refused() {
        assert!(open_preflight(&open_terms(500), BUYER, JOB, true, DEADLINE - 1).is_err());
    }

    #[test]
    fn an_open_with_terms_that_cannot_settle_is_refused() {
        let now = DEADLINE - 1;
        assert!(open_preflight(&open_terms(0), BUYER, JOB, false, now).is_err());
        let with = |provider, pay_to, refund_to| Instruction::Open {
            job_ref: [9; 32],
            provider,
            pay_to,
            refund_to,
            amount: 500,
            deadline: DEADLINE,
            controller: None,
        };
        for terms in [
            with(BUYER, PROVIDER, BUYER),
            with(PROVIDER, JOB, BUYER),
            with(PROVIDER, PROVIDER, JOB),
        ] {
            assert!(
                open_preflight(&terms, BUYER, JOB, false, now).is_err(),
                "{terms:?}"
            );
        }
    }

    #[test]
    fn a_job_with_nothing_left_is_not_returned() {
        let paid_in_full = record(JobState::Open, 500, 0);
        assert!(preflight(&Call::Return, &paid_in_full, DEADLINE - 1).is_err());
    }

    #[test]
    fn a_call_with_nothing_to_move_is_refused() {
        assert!(preflight(&Call::Claim, &record(JobState::Open, 200, 200), 0).is_err());
        assert!(preflight(&Call::Release(301), &record(JobState::Open, 200, 0), 0).is_err());
        assert!(preflight(&Call::Release(0), &record(JobState::Open, 0, 0), 0).is_err());
        assert!(preflight(&Call::Refund, &record(JobState::Open, 500, 0), DEADLINE).is_err());
    }

    #[test]
    fn a_call_the_job_state_rules_out_is_refused() {
        let delivered = record(JobState::Delivered, 500, 0);
        for call in [Call::Deliver, Call::Release(1), Call::Refund, Call::Return] {
            assert!(
                preflight(&call, &delivered, DEADLINE - 1).is_err(),
                "{call:?}"
            );
        }
        let mut controlled_and_delivered = record(JobState::Open, 0, 0);
        controlled_and_delivered.result = Some([4; 32]);
        assert!(preflight(&Call::Deliver, &controlled_and_delivered, DEADLINE - 1).is_err());
        let refunded = record(JobState::Refunded, 0, 0);
        assert!(preflight(&Call::Refund, &refunded, DEADLINE).is_err());
    }
}
