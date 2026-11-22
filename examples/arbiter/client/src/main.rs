//! Sends the example arbiter's calls from a LEZ wallet (`LEE_WALLET_HOME_DIR`): open a job
//! through it, and the judge's release and return. The parties claim and refund with the escrow's
//! own CLI. Each call prints its transaction, then the job as the escrow holds it.

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result, bail};
use clap::{Parser, Subcommand};
use lee_core::account::{AccountId, Actor, Balance};
use logos_escrow_arbiter::{ArbiterInstruction, Case, Decision, case_account_id};
use logos_escrow_core::{Hash32, Job, job_account_id};
use wallet::{AccountIdentity, AccountMention, WalletCore, WalletSequencerClient};

/// Where the instruction goes: the first account given, the signer's own actor under the arbiter.
const SIGNER_ACTOR: usize = 0;

#[derive(Parser)]
#[command(about = "Drive the example arbiter from a LEZ wallet")]
struct Args {
    /// The arbiter's program id; logos-devnet exports it.
    #[arg(long, env = "LOGOS_PROGRAM_ARBITER", global = true)]
    arbiter: Option<AccountId>,
    /// The escrow's program id; logos-devnet exports it.
    #[arg(long, env = "LOGOS_PROGRAM_ESCROW", global = true)]
    escrow: Option<AccountId>,
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

#[derive(Subcommand)]
enum Command {
    /// Buyer: lock `amount` for `provider` for `in_secs`, with `judge` deciding.
    Open {
        #[command(flatten)]
        job: JobArgs,
        #[arg(long)]
        judge: AccountId,
        #[arg(long)]
        provider: AccountId,
        #[arg(long)]
        pay_to: AccountId,
        #[arg(long)]
        refund_to: AccountId,
        #[arg(long)]
        amount: Balance,
        #[arg(long)]
        in_secs: u64,
    },
    /// Judge: let the provider claim `amount` more.
    Release {
        #[command(flatten)]
        job: JobArgs,
        #[arg(long)]
        judge: AccountId,
        #[arg(long)]
        amount: Balance,
    },
    /// Judge: give what was never released back to the buyer.
    Return {
        #[command(flatten)]
        job: JobArgs,
        #[arg(long)]
        judge: AccountId,
    },
    /// Provider: check the job's case before working on it, and print the job.
    Show {
        #[command(flatten)]
        job: JobArgs,
    },
}

fn parse_hash(text: &str) -> Result<Hash32> {
    let bytes = hex::decode(text).context("not hex")?;
    <Hash32>::try_from(bytes).map_err(|_| anyhow::anyhow!("expected 32 bytes"))
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let arbiter = args
        .arbiter
        .context("set --arbiter or LOGOS_PROGRAM_ARBITER")?;
    let escrow = args
        .escrow
        .context("set --escrow or LOGOS_PROGRAM_ESCROW")?;
    let wallet = WalletCore::from_env().context("open the wallet at LEE_WALLET_HOME_DIR")?;
    let client = Client {
        wallet,
        arbiter,
        escrow,
    };

    match args.command {
        Command::Open {
            job,
            judge,
            provider,
            pay_to,
            refund_to,
            amount,
            in_secs,
        } => {
            let now = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
            let open = ArbiterInstruction::Open {
                escrow,
                judge,
                job_ref: job.job_ref,
                provider,
                pay_to,
                refund_to,
                amount,
                deadline: now + in_secs * 1000,
            };
            // The buyer's escrow actor and both native balances, for the escrow's Open.
            let job_account = client.job_account(&job);
            // The wallet names one account by one identity in a transaction: the buyer signs.
            let more = vec![
                AccountIdentity::Public(job.buyer).select_program_actor_state(escrow),
                AccountIdentity::Public(job.buyer).balance(),
                AccountIdentity::PublicNoSign(job_account).balance(),
            ];
            client.send(&job, job.buyer, more, &open).await
        }
        Command::Release { job, judge, amount } => {
            let decide = ArbiterInstruction::Decide {
                escrow,
                buyer: job.buyer,
                job_ref: job.job_ref,
                decision: Decision::Release { amount },
            };
            let party = AccountIdentity::PublicNoSign(job.buyer).select_program_actor_state(escrow);
            client.send(&job, judge, vec![party], &decide).await
        }
        Command::Show { job } => client.show(&job).await,
        Command::Return { job, judge } => {
            let provider = client.job(&job).await?.provider;
            let decide = ArbiterInstruction::Decide {
                escrow,
                buyer: job.buyer,
                job_ref: job.job_ref,
                decision: Decision::Return,
            };
            let party = AccountIdentity::PublicNoSign(provider).select_program_actor_state(escrow);
            client.send(&job, judge, vec![party], &decide).await
        }
    }
}

struct Client<C: WalletSequencerClient> {
    wallet: WalletCore<C>,
    arbiter: AccountId,
    escrow: AccountId,
}

impl<C: WalletSequencerClient> Client<C> {
    fn job_account(&self, job: &JobArgs) -> AccountId {
        job_account_id(&self.escrow, &job.buyer, &job.job_ref)
    }

    /// Sends one arbiter call to `signer`'s own actor under the arbiter, declaring the case, the
    /// job and `more`.
    async fn send(
        &self,
        job: &JobArgs,
        signer: AccountId,
        more: Vec<AccountMention>,
        instruction: &ArbiterInstruction,
    ) -> Result<()> {
        let job_account = self.job_account(job);
        let mut accounts = vec![
            AccountIdentity::Public(signer).select_program_actor_state(self.arbiter),
            AccountIdentity::PublicNoSign(case_account_id(&self.arbiter, &job_account))
                .select_program_actor_state(self.arbiter),
            AccountIdentity::PublicNoSign(job_account).select_program_actor_state(self.escrow),
        ];
        accounts.extend(more);
        let hash = self
            .wallet
            .send_pub_tx(accounts, SIGNER_ACTOR, borsh::to_vec(instruction)?)
            .await
            .map_err(|error| anyhow::anyhow!("send failed: {error:?}"))?;
        let (_, block) = self
            .wallet
            .poll_transaction(hash)
            .await
            .context("transaction not included")?;
        println!("tx {hash} in block {block}");
        // A refused public call is still included, so the job shows whether it worked.
        let record = self.job(job).await?;
        println!(
            "job {job_account}: {:?}, released {}, claimed {}",
            record.state, record.released, record.claimed
        );
        Ok(())
    }

    /// Prints the case and the job. A job opened straight on the escrow can still name the
    /// arbiter as its controller, but then it has no case and nobody can ever decide it.
    async fn show(&self, job: &JobArgs) -> Result<()> {
        let case_account = case_account_id(&self.arbiter, &self.job_account(job));
        let shard = self
            .wallet
            .get_account_public(case_account)
            .await?
            .unwrap_or_default()
            .data
            .actor_state(self.arbiter)
            .to_vec();
        let record = self.job(job).await?;
        if shard.is_empty() {
            bail!(
                "no case at {case_account}: the job wasn't opened through this arbiter, so no \
                 judge can ever decide it"
            );
        }
        let case: Case = borsh::from_slice(&shard)?;
        // The arbiter calls the escrow a case names with the judge's signature, so a judge
        // decides only cases that name the real one.
        if case.escrow != self.escrow
            || record.controller != Some(Actor::new(case_account, self.arbiter))
        {
            bail!("the case or the job names another escrow or controller: don't work on it");
        }
        println!("judge {}", case.judge);
        println!(
            "job {}: {:?}, amount {}, released {}, claimed {}, pay_to {}, deadline {}",
            self.job_account(job),
            record.state,
            record.amount,
            record.released,
            record.claimed,
            record.pay_to,
            record.deadline
        );
        Ok(())
    }

    async fn job(&self, job: &JobArgs) -> Result<Job> {
        let account = self
            .wallet
            .get_account_public(self.job_account(job))
            .await?
            .unwrap_or_default();
        let state = account.data.actor_state(self.escrow);
        if state.is_empty() {
            bail!("no job at {}", self.job_account(job));
        }
        Ok(borsh::from_slice(state)?)
    }
}
