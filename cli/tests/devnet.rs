//! Every escrow flow against a running LEZ v0.4 devnet, through the real CLI and the LEZ wallet it
//! uses, with public and private parties and a program acting as controller.
//!
//! ```bash
//! make build && logos-devnet reset
//! logos-devnet exec -- cargo test -p logos_escrow_cli --test devnet -- --ignored
//! ```
//!
//! Run it on a fresh chain: the copied wallet makes the same new private accounts every run, so a
//! second run on one chain collides with the first.

use std::{
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use lee_core::account::{AccountId, Balance};
use logos_escrow_core::{Decision, Instruction};
use wallet::{
    AccountIdentity, WalletCore,
    program_facades::{CreditDelivery, native_token_transfer::NativeTokenTransfer},
};

const AMOUNT: Balance = 1_000_000;

struct Devnet {
    program: AccountId,
    /// The test-only controller, which relays whatever escrow call it is given.
    controller: AccountId,
    home: PathBuf,
    payer: AccountId,
    buyer: AccountId,
    provider: AccountId,
}

fn env(name: &str) -> String {
    std::env::var(name)
        .unwrap_or_else(|_| panic!("{name} is unset: run this under `logos-devnet exec`"))
}

impl Devnet {
    /// A copy of the devnet's funded `parties` wallet, so a run leaves the original untouched.
    fn new() -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let home = std::env::temp_dir().join(format!("logos-escrow-devnet-{nanos}"));
        std::fs::create_dir_all(&home).expect("make the wallet copy");
        let group = PathBuf::from(env("LOGOS_DEVNET_ACCOUNTS_PARTIES_WALLET"));
        for file in ["wallet_config.json", "storage.json"] {
            std::fs::copy(group.join(file), home.join(file)).expect("copy the group wallet");
        }
        let accounts: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(env("LOGOS_DEVNET_ACCOUNTS_PARTIES"))
                .expect("read the account group"),
        )
        .expect("the account group is JSON");
        let ids: Vec<AccountId> = accounts["accounts"]
            .as_array()
            .expect("an accounts list")
            .iter()
            .map(|account| {
                account["id"]
                    .as_str()
                    .expect("an id")
                    .parse()
                    .expect("a base58 id")
            })
            .collect();
        let [payer, buyer, provider] = ids[..] else {
            panic!("the parties group has {} accounts, not 3", ids.len());
        };
        let id = |name: &str| env(name).parse().expect("a base58 program id");
        Self {
            program: id("LOGOS_PROGRAM_ESCROW"),
            controller: id("LOGOS_PROGRAM_TEST_CONTROLLER"),
            home,
            payer,
            buyer,
            provider,
        }
    }

    /// The devnet's group wallets are unencrypted, which an empty password opens.
    fn wallet(&self) -> WalletCore<impl wallet::WalletSequencerClient> {
        WalletCore::new_update_chain(
            self.home.join("wallet_config.json"),
            self.home.join("storage.json"),
            None,
            "",
        )
        .expect("open the wallet")
    }

    /// Runs the CLI, and returns whether it succeeded and what it printed.
    fn run(&self, args: &[&str]) -> (bool, String) {
        let elf = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../methods/guest/target/riscv32im-risc0-zkvm-elf/docker/logos_escrow.bin");
        let output = Command::new(env!("CARGO_BIN_EXE_logos-escrow"))
            .args(args)
            .env("LEE_WALLET_HOME_DIR", &self.home)
            .env("LOGOS_PROGRAM_ESCROW", self.program.to_string())
            .env("LOGOS_ESCROW_ELF", elf)
            .output()
            .expect("run the CLI");
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        (output.status.success(), text)
    }

    /// Runs the CLI and returns its output, failing the test if it fails.
    fn cli(&self, args: &[&str]) -> String {
        let (succeeded, text) = self.run(args);
        assert!(succeeded, "logos-escrow {args:?} failed:\n{text}");
        text
    }

    /// Runs the CLI expecting it to fail, and returns its output.
    fn cli_fails(&self, args: &[&str]) -> String {
        let (succeeded, text) = self.run(args);
        assert!(!succeeded, "logos-escrow {args:?} succeeded:\n{text}");
        text
    }

    /// Runs one escrow call and returns the job's state afterwards.
    fn call(&self, args: &[&str]) -> String {
        let text = self.cli(args);
        text.lines()
            .rev()
            .find_map(|line| line.split("state: ").nth(1))
            .map(|rest| {
                rest.split(|c: char| !c.is_alphanumeric())
                    .next()
                    .unwrap_or("")
                    .to_owned()
            })
            .unwrap_or_else(|| panic!("no job state in:\n{text}"))
    }

    /// Has the controller decide on `job`, straight at the job's actor: the payer signs the
    /// call to the controller, which decides from the payer's actor under it. No party takes part.
    async fn decide(
        &self,
        job: AccountId,
        buyer: AccountId,
        job_ref: [u8; 32],
        decision: Decision,
    ) {
        let instruction = Instruction::Decide {
            buyer,
            job_ref,
            decision,
        };
        let relay = (
            self.program,
            job,
            Vec::<[u8; 32]>::new(),
            borsh::to_vec(&instruction).expect("instruction serializes"),
        );
        let accounts = vec![
            AccountIdentity::Public(self.payer).select_program_actor_state(self.controller),
            AccountIdentity::PublicNoSign(job).select_program_actor_state(self.program),
        ];
        let wallet = self.wallet();
        let hash = wallet
            .send_pub_tx(
                accounts,
                0,
                borsh::to_vec(&relay).expect("relay serializes"),
            )
            .await
            .expect("send the decision");
        wallet
            .poll_transaction(hash)
            .await
            .expect("the decision lands");
    }

    async fn public_balance(&self, id: AccountId) -> Balance {
        self.wallet()
            .get_account_balance(id)
            .await
            .expect("read a balance")
    }

    /// A private account's balance, as the wallet holding its keys sees it after a sync.
    async fn private_balance(&self, id: &str) -> Balance {
        let mut wallet = self.wallet();
        wallet.sync_to_latest_block().await.expect("sync");
        wallet.store_persistent_data().expect("save the wallet");
        let id: AccountId = id.parse().expect("an account id");
        wallet.get_account_private(id).map_or(0, |account| {
            account.data.native_balance().expect("a balance")
        })
    }
}

fn job_ref() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    format!("{nanos:064x}")
}

#[tokio::test]
#[ignore = "needs a fresh devnet: logos-devnet reset, then run this under logos-devnet exec"]
async fn every_flow_settles_on_a_devnet() {
    let devnet = Devnet::new();
    let payer = devnet.payer.to_string();
    let (buyer, provider) = (devnet.buyer.to_string(), devnet.provider.to_string());
    let amount = AMOUNT.to_string();
    let open = |job: &str, secs: &str, controller: Option<&str>| -> Vec<String> {
        let mut args = vec![
            "--payer",
            &payer,
            "open",
            "--buyer",
            &buyer,
            "--job-ref",
            job,
            "--provider",
            &provider,
            "--pay-to",
            &provider,
            "--refund-to",
            &buyer,
            "--amount",
            &amount,
            "--in-secs",
            secs,
        ];
        if let Some(controller) = controller {
            // The controller decides from the payer's actor under it.
            args.extend(["--controller", controller, "--controller-account", &payer]);
        }
        args.into_iter().map(str::to_owned).collect()
    };
    let call =
        |args: Vec<String>| devnet.call(&args.iter().map(String::as_str).collect::<Vec<_>>());
    let on = |job: &str, command: &str, extra: &[&str]| -> Vec<String> {
        [
            "--payer",
            payer.as_str(),
            command,
            "--buyer",
            buyer.as_str(),
            "--job-ref",
            job,
        ]
        .into_iter()
        .chain(extra.iter().copied())
        .map(str::to_owned)
        .collect()
    };

    // Public parties, paid to themselves: open, deliver, claim.
    let job = job_ref();
    let before = devnet.public_balance(devnet.provider).await;
    assert_eq!(call(open(&job, "600", None)), "Open");
    // A claim before delivery is refused with WrongAmount (10). `--force` skips the CLI's own
    // check, and then the wallet's simulation of the call stops it before it's sent.
    let mut early = on(&job, "claim", &[]);
    early.insert(2, "--force".to_owned());
    let refused = devnet.cli_fails(&early.iter().map(String::as_str).collect::<Vec<_>>());
    assert!(refused.contains("non-zero code 10"), "{refused}");
    assert_eq!(call(on(&job, "show", &[])), "Open");
    assert_eq!(call(on(&job, "deliver", &["--result", &job])), "Delivered");
    assert_eq!(call(on(&job, "claim", &[])), "Delivered");
    assert_eq!(
        devnet.public_balance(devnet.provider).await,
        before + AMOUNT
    );

    // Paid to a public account the wallet holds no key for: the CLI won't place the payout
    // until told it's public, then pays it.
    let job = job_ref();
    let elsewhere = devnet.controller;
    let before = devnet.public_balance(elsewhere).await;
    let mut to_elsewhere = open(&job, "600", None);
    to_elsewhere[10] = elsewhere.to_string();
    assert_eq!(to_elsewhere[9], "--pay-to");
    assert_eq!(call(to_elsewhere), "Open");
    assert_eq!(call(on(&job, "deliver", &["--result", &job])), "Delivered");
    let unplaced = devnet.cli_fails(
        &on(&job, "claim", &[])
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
    );
    assert!(
        unplaced.contains("can't tell what kind of account"),
        "{unplaced}"
    );
    assert_eq!(call(on(&job, "claim", &["--public-payee"])), "Delivered");
    assert_eq!(devnet.public_balance(elsewhere).await, before + AMOUNT);

    // Public parties: open, the deadline passes, refund.
    let job = job_ref();
    let before = devnet.public_balance(devnet.buyer).await;
    assert_eq!(call(open(&job, "4", None)), "Open");
    let job_bytes = <[u8; 32]>::try_from(hex::decode(&job).expect("hex")).expect("32 bytes");
    let locked = logos_escrow_core::job_account_id(&devnet.program, &devnet.buyer, &job_bytes);
    assert_eq!(devnet.public_balance(locked).await, AMOUNT);
    tokio::time::sleep(Duration::from_secs(8)).await;
    assert_eq!(call(on(&job, "refund", &[])), "Refunded");
    assert_eq!(devnet.public_balance(devnet.buyer).await, before);

    // A controlled job: the buyer and the controller each release a part, the provider claims
    // both, the controller returns the rest and the buyer refunds it.
    let job = job_ref();
    let controller = devnet.controller.to_string();
    let (provider_before, buyer_before) = (
        devnet.public_balance(devnet.provider).await,
        devnet.public_balance(devnet.buyer).await,
    );
    assert_eq!(call(open(&job, "600", Some(&controller))), "Open");
    // Delivering a controlled job releases nothing.
    assert_eq!(call(on(&job, "deliver", &["--result", &job])), "Open");
    let part = (AMOUNT / 4).to_string();
    assert_eq!(call(on(&job, "release", &["--amount", &part])), "Open");
    let job_ref_bytes = <[u8; 32]>::try_from(hex::decode(&job).expect("hex")).expect("32 bytes");
    let job_account =
        logos_escrow_core::job_account_id(&devnet.program, &devnet.buyer, &job_ref_bytes);
    devnet
        .decide(
            job_account,
            devnet.buyer,
            job_ref_bytes,
            Decision::Release { amount: AMOUNT / 4 },
        )
        .await;
    assert_eq!(call(on(&job, "claim", &[])), "Open");
    devnet
        .decide(job_account, devnet.buyer, job_ref_bytes, Decision::Return)
        .await;
    assert_eq!(call(on(&job, "refund", &[])), "Refunded");
    assert_eq!(
        devnet.public_balance(devnet.provider).await,
        provider_before + AMOUNT / 2
    );
    assert_eq!(
        devnet.public_balance(devnet.buyer).await,
        buyer_before - AMOUNT / 2
    );

    // Private parties, funded by a shielded transfer, paid to fresh private payout addresses.
    let mut wallet = devnet.wallet();
    let (private_buyer, _) = wallet.create_new_account_private(None);
    let (private_provider, _) = wallet.create_new_account_private(None);
    // Private transactions pay their fees in LEZ 0.4, from an owned private account: this one.
    let (private_fees, _) = wallet.create_new_account_private(None);
    wallet.store_persistent_data().expect("save the wallet");
    for (account, amount) in [(private_buyer, 20 * AMOUNT), (private_fees, 100 * AMOUNT)] {
        let (hash, _) = NativeTokenTransfer(&wallet)
            .transfer(
                AccountIdentity::Public(devnet.payer),
                AccountIdentity::PrivateOwned(account),
                amount,
                CreditDelivery::Automatic,
            )
            .await
            .expect("shield funds");
        wallet
            .poll_transaction(hash)
            .await
            .expect("the shielded transfer lands");
        wallet.sync_to_latest_block().await.expect("sync");
    }
    wallet.store_persistent_data().expect("save the wallet");
    drop(wallet);
    let (pbuyer, pprovider) = (private_buyer.to_string(), private_provider.to_string());
    let fees = private_fees.to_string();

    // "decided": a job between private parties, released by its controller in a public call that
    // names no party, so neither has to be online for it.
    for flow in ["claim", "return", "release", "pre-funded", "decided"] {
        let job = job_ref();
        let pay_to = devnet.cli(&["payout-address"]).trim().to_owned();
        if flow == "pre-funded" {
            // Someone pays into the fresh pay_to first, so it holds a note before the claim.
            let mut wallet = devnet.wallet();
            wallet.set_private_fee_payer(Some(private_fees));
            let (hash, _) = NativeTokenTransfer(&wallet)
                .transfer(
                    AccountIdentity::Public(devnet.payer),
                    AccountIdentity::PrivateOwned(pay_to.parse().expect("an account id")),
                    1,
                    CreditDelivery::Automatic,
                )
                .await
                .expect("pay into the pay_to first");
            wallet
                .poll_transaction(hash)
                .await
                .expect("the transfer lands");
            wallet.sync_to_latest_block().await.expect("sync");
            wallet.store_persistent_data().expect("save the wallet");
        }
        let refund_to = devnet.cli(&["payout-address"]).trim().to_owned();
        let controller = devnet.controller.to_string();
        let mut open = vec![
            "--payer",
            &fees,
            "open",
            "--buyer",
            &pbuyer,
            "--job-ref",
            &job,
            "--provider",
            &pprovider,
            "--pay-to",
            &pay_to,
            "--refund-to",
            &refund_to,
            "--amount",
            &amount,
            "--in-secs",
            "600",
        ];
        if flow == "decided" {
            open.extend(["--controller", &controller, "--controller-account", &payer]);
        }
        assert_eq!(devnet.call(&open), "Open", "{flow}");
        let on = |command: &str, extra: &[&str]| -> Vec<String> {
            [
                "--payer",
                fees.as_str(),
                command,
                "--buyer",
                pbuyer.as_str(),
                "--job-ref",
                job.as_str(),
            ]
            .into_iter()
            .chain(extra.iter().copied())
            .map(str::to_owned)
            .collect()
        };
        match flow {
            "claim" => {
                assert_eq!(call(on("deliver", &["--result", &job])), "Delivered");
                assert_eq!(call(on("claim", &[])), "Delivered");
                assert_eq!(devnet.private_balance(&pay_to).await, AMOUNT);
            }
            "return" => {
                assert_eq!(call(on("return", &[])), "Returned");
                assert_eq!(call(on("refund", &[])), "Refunded");
                assert_eq!(devnet.private_balance(&refund_to).await, AMOUNT);
            }
            "release" => {
                assert_eq!(call(on("release", &[])), "Open");
                assert_eq!(call(on("claim", &[])), "Open");
                assert_eq!(devnet.private_balance(&pay_to).await, AMOUNT);
            }
            "pre-funded" => {
                assert_eq!(call(on("deliver", &["--result", &job])), "Delivered");
                assert_eq!(call(on("claim", &[])), "Delivered");
                assert_eq!(devnet.private_balance(&pay_to).await, AMOUNT + 1);
            }
            _ => {
                let job_ref = <[u8; 32]>::try_from(hex::decode(&job).expect("hex")).expect("32");
                let job_account =
                    logos_escrow_core::job_account_id(&devnet.program, &private_buyer, &job_ref);
                devnet
                    .decide(
                        job_account,
                        private_buyer,
                        job_ref,
                        Decision::Release { amount: AMOUNT },
                    )
                    .await;
                assert_eq!(call(on("claim", &[])), "Open");
                assert_eq!(devnet.private_balance(&pay_to).await, AMOUNT);
            }
        }
    }
    std::fs::remove_dir_all(&devnet.home).ok();
}
