//! Calls the escrow program on a LEZ sequencer from a LEZ wallet (`LEE_WALLET_HOME_DIR`).
//!
//! A call goes public through `WalletCore::send_pub_tx_paid_by`, which `lez_core`'s
//! `send_generic_public_transaction` calls, or private through
//! `WalletCore::send_privacy_preserving_tx` when the signer is one of the wallet's private
//! accounts or the payee is a private payout address. The job record is read back with
//! `getAccount`.

use std::{
    collections::HashMap,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context as _, Result, bail};
use clap::{Parser, Subcommand};
use lee::{privacy_preserving_transaction::circuit::ProgramWithDependencies, program::Program};
use lee_core::{
    Identifier, NullifierPublicKey,
    account::{AccountId, Balance},
    encryption::ViewingPublicKey,
    program::PrivateAccountKind,
};
use logos_escrow_core::{Hash32, Instruction, Job, JobState, job_account_id};
use wallet::{AccountIdentity, AccountMention, WalletCore};

#[derive(Parser)]
#[command(about = "Drive the logos-escrow program from a LEZ wallet")]
struct Args {
    /// The escrow program's header account id (base58).
    #[arg(long, env = "LOGOS_ESCROW_PROGRAM", global = true)]
    program: Option<AccountId>,
    /// Send the call even when the job record says it will be refused, which a public call
    /// still pays for.
    #[arg(long, global = true)]
    force: bool,
    /// A wallet account that pays a public transaction's fee; by default the signer pays.
    /// Private transactions are fee-exempt.
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
    /// The payout address file, when the address is a fresh private account (see
    /// `payout-address`).
    #[arg(long)]
    payee_address: Option<PathBuf>,
    /// Pay a public account this wallet holds no key for. Without it, the CLI refuses to send a
    /// payout it can't place, because a private address paid publicly is burned.
    #[arg(long)]
    public_payee: bool,
}

#[derive(Subcommand)]
enum Command {
    /// Print the job account for a buyer and job reference.
    JobAccount(JobArgs),
    /// Print a job's record and the balance it holds.
    Show(JobArgs),
    /// Make a fresh private payout address under one of the wallet's private accounts' keys.
    /// Prints the account id to use in `open`, and writes its key file to `--out`. Keep that file:
    /// claiming or refunding to a fresh address needs it.
    PayoutAddress {
        /// The wallet's private account whose keys own the address.
        #[arg(long)]
        owner: AccountId,
        #[arg(long)]
        out: PathBuf,
    },
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

/// A private account that only its owner's keys can spend, given out so another party can pay
/// into it once.
struct PayoutAddress {
    npk: NullifierPublicKey,
    vpk: ViewingPublicKey,
    identifier: Identifier,
}

impl PayoutAddress {
    fn account_id(&self) -> AccountId {
        AccountId::for_regular_private_account(&self.npk, &self.vpk, self.identifier)
    }

    /// Three hex lines: the nullifier public key, the viewing public key, the identifier.
    fn to_file(&self) -> String {
        format!(
            "{}\n{}\n{}\n",
            hex::encode(self.npk.0),
            hex::encode(self.vpk.to_bytes()),
            hex::encode(self.identifier.value())
        )
    }

    fn from_file(path: &PathBuf) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("read payout address {}", path.display()))?;
        let mut lines = text.lines().map(str::trim).filter(|line| !line.is_empty());
        let mut next = |what: &str| {
            lines
                .next()
                .with_context(|| format!("payout address file is missing the {what}"))
        };
        let npk = NullifierPublicKey(
            hex::decode(next("nullifier public key")?)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("nullifier public key must be 32 bytes"))?,
        );
        let vpk = ViewingPublicKey::from_bytes(hex::decode(next("viewing public key")?)?)
            .map_err(|error| anyhow::anyhow!("viewing public key: {error}"))?;
        let identifier = Identifier::new(
            hex::decode(next("identifier")?)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("identifier must be 32 bytes"))?,
        );
        Ok(Self {
            npk,
            vpk,
            identifier,
        })
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let program = args
        .program
        .context("set --program or LOGOS_ESCROW_PROGRAM")?;
    let force = args.force;
    let wallet = WalletCore::from_env().context("open the wallet at LEE_WALLET_HOME_DIR")?;
    let mut escrow = Escrow {
        wallet,
        program,
        payer: args.payer,
        elf: args.elf,
    };

    match args.command {
        Command::JobAccount(job) => println!("{}", escrow.job_account(&job)),
        Command::Show(job) => escrow.show(&job).await?,
        Command::PayoutAddress { owner, out } => {
            let found = escrow
                .wallet
                .storage()
                .key_chain()
                .private_account(owner)
                .with_context(|| format!("{owner} is not one of this wallet's private accounts"))?;
            let address = PayoutAddress {
                npk: found.key_chain.nullifier_public_key,
                vpk: found.key_chain.viewing_public_key.clone(),
                identifier: wallet::cli::identifier_or_random(None),
            };
            // The identifier exists only in this file, and a fresh address can't be claimed to
            // without it, so never overwrite another job's address.
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&out)
                .with_context(|| format!("create {} (it must not exist yet)", out.display()))?;
            std::io::Write::write_all(&mut file, address.to_file().as_bytes())?;
            println!("{}", address.account_id());
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
            check(force, open_preflight(deadline, now_ms()?))?;
            let instruction = Instruction::Open {
                job_ref: job.job_ref,
                provider,
                pay_to,
                refund_to,
                amount,
                deadline,
                controller,
            };
            let accounts = vec![
                escrow.signs(job.buyer),
                escrow.mention(escrow.job_account(&job)),
            ];
            escrow.send(&job, accounts, &instruction).await?;
        }
        Command::Deliver { job, result } => {
            let record = escrow.record(&job).await?;
            check(force, preflight(&Call::Deliver, &record, now_ms()?))?;
            let instruction = Instruction::Deliver {
                result,
                deadline: record.deadline,
            };
            let accounts = vec![
                escrow.signs(record.provider),
                escrow.mention(escrow.job_account(&job)),
            ];
            escrow.send(&job, accounts, &instruction).await?;
        }
        Command::Claim(payout) => {
            // Sync first, so a payout address someone already paid into is used as the wallet's own.
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
            let accounts = vec![
                escrow.signs(job.buyer),
                escrow.mention(escrow.job_account(&job)),
            ];
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
            let accounts = vec![
                escrow.signs(record.provider),
                escrow.mention(escrow.job_account(&job)),
            ];
            escrow.send(&job, accounts, &Instruction::Return).await?;
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
/// milliseconds). A refused public call is still included and charged, and one outside the
/// deadline window pays its whole gas limit, so the CLI checks before it sends. The clock is
/// this machine's, which can differ a little from the block's.
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
        Call::Deliver if now >= record.deadline => Err(
            "the deadline has passed, so LEZ would refuse the call and charge its whole gas limit"
                .into(),
        ),
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
        Call::Refund if open && now < record.deadline => Err(
            "the deadline hasn't passed, so LEZ would refuse the call and charge its whole gas \
             limit"
                .into(),
        ),
        Call::Refund if record.unreleased() == 0 => Err("nothing is left to refund".into()),
        Call::Return if !open => Err(format!(
            "only an open job can be returned: it is {:?}",
            record.state
        )),
        _ => Ok(()),
    }
}

/// An `Open` must land before its deadline.
fn open_preflight(deadline: u64, now: u64) -> Result<(), String> {
    if now >= deadline {
        Err(
            "the deadline has passed, so LEZ would refuse the call and charge its whole gas limit"
                .into(),
        )
    } else {
        Ok(())
    }
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

struct Escrow {
    wallet: WalletCore,
    program: AccountId,
    payer: Option<AccountId>,
    elf: PathBuf,
}

impl Escrow {
    fn job_account(&self, job: &JobArgs) -> AccountId {
        job_account_id(&self.program, &job.buyer, &job.job_ref)
    }

    /// The signer: one of the wallet's private accounts if it holds one with this id, otherwise a
    /// public account. Every account selects the escrow program's shard; the program builds the
    /// native-balance selectors for the transfers it chains.
    fn signs(&self, account_id: AccountId) -> AccountMention {
        let private = self
            .wallet
            .storage()
            .key_chain()
            .private_account(account_id)
            .is_some();
        let identity = if private {
            AccountIdentity::PrivateOwned(account_id)
        } else {
            AccountIdentity::Public(account_id)
        };
        AccountMention {
            identity,
            program_account_id: self.program,
        }
    }

    /// An account named without signing, selecting the escrow program's shard.
    fn mention(&self, account_id: AccountId) -> AccountMention {
        AccountMention {
            identity: AccountIdentity::PublicNoSign(account_id),
            program_account_id: self.program,
        }
    }

    /// The signer, the job account and, unless the job pays the signer itself, the payee.
    fn payout_accounts(
        &self,
        payout: &PayoutArgs,
        signer: AccountId,
        payee: AccountId,
    ) -> Result<Vec<AccountMention>> {
        let mut accounts = vec![
            self.signs(signer),
            self.mention(self.job_account(&payout.job)),
        ];
        if payee != signer {
            accounts.push(self.payee(payee, payout)?);
        }
        Ok(accounts)
    }

    /// The payout address, as the account kind the wallet can pay into: one of its own private
    /// accounts, a fresh private account from an address file, or a public account.
    fn payee(&self, payee: AccountId, payout: &PayoutArgs) -> Result<AccountMention> {
        let key_chain = self.wallet.storage().key_chain();
        let identity = if key_chain.private_account(payee).is_some() {
            AccountIdentity::PrivateOwned(payee)
        } else if let Some(path) = &payout.payee_address {
            let address = PayoutAddress::from_file(path)?;
            if address.account_id() != payee {
                bail!(
                    "{} is the address {}, but the job pays {payee}",
                    path.display(),
                    address.account_id()
                );
            }
            AccountIdentity::PrivateForeign {
                npk: address.npk,
                vpk: address.vpk,
                kind: PrivateAccountKind::Regular(address.identifier),
            }
        } else if payout.public_payee || key_chain.pub_account_signing_key(payee).is_some() {
            AccountIdentity::PublicNoSign(payee)
        } else {
            bail!(
                "can't tell what kind of account {payee} is: pass --payee-address for a private \
                 payout address, or --public-payee for a public account"
            );
        };
        Ok(AccountMention {
            identity,
            program_account_id: self.program,
        })
    }

    async fn record(&self, job: &JobArgs) -> Result<Job> {
        let account = self
            .wallet
            .get_account_public(self.job_account(job))
            .await?;
        let shard = account.data.shard(self.program);
        if shard.is_empty() {
            bail!("no job at {}", self.job_account(job));
        }
        Ok(borsh::from_slice(shard)?)
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
            let program = ProgramWithDependencies::new(
                Program::new(elf.into())?,
                self.program,
                HashMap::new(),
            );
            println!("proving locally...");
            let (hash, _) = self
                .wallet
                .send_privacy_preserving_tx(accounts, data, &program)
                .await
                .map_err(|error| anyhow::anyhow!("send failed: {error:?}"))?;
            hash
        } else {
            self.wallet
                .send_pub_tx_paid_by(accounts, data, self.program, self.payer)
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
        assert!(open_preflight(DEADLINE, DEADLINE).is_err());
        assert_eq!(open_preflight(DEADLINE, DEADLINE - 1), Ok(()));
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

    fn address() -> PayoutAddress {
        PayoutAddress {
            npk: NullifierPublicKey([1; 32]),
            vpk: ViewingPublicKey::from_bytes(vec![2; 1184]).expect("1184-byte key"),
            identifier: Identifier::new([3; 32]),
        }
    }

    fn written(name: &str, text: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "logos-escrow-test-{}-{name}.addr",
            std::process::id()
        ));
        std::fs::write(&path, text).expect("write the address file");
        path
    }

    #[test]
    fn a_payout_address_file_round_trips_to_the_same_account() {
        let path = written("round-trip", &address().to_file());
        let read = PayoutAddress::from_file(&path).expect("reads back");
        std::fs::remove_file(&path).ok();
        assert_eq!(read.account_id(), address().account_id());
        assert_eq!(read.identifier, address().identifier);
    }

    /// Computed independently: SHA-256 of the 32-byte prefix, npk, vpk and identifier, with
    /// Python's `hashlib`.
    #[test]
    fn the_address_is_the_lez_private_account_id_of_its_keys() {
        assert_eq!(
            address().account_id().to_string(),
            "9aook7Yh6sHfiPGHwWS2AG3HEhbKZAtaWj8TryeZRfhv"
        );
    }

    #[test]
    fn a_truncated_address_file_is_refused() {
        let full = address().to_file();
        let two_lines: String = full
            .lines()
            .take(2)
            .map(|line| format!("{line}\n"))
            .collect();
        let path = written("truncated", &two_lines);
        let read = PayoutAddress::from_file(&path);
        std::fs::remove_file(&path).ok();
        assert!(read.is_err());
    }
}
