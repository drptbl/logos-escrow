# Arbiter

An escrow controller you can start from. The buyer opens a job through the arbiter and names a judge, and only that judge can make the arbiter pay the provider or give the deposit back. The buyer and the provider still claim and refund on the escrow themselves, so the judge decides who gets the money but never where it goes.

## How it works

| Call | Sent to | What happens |
| --- | --- | --- |
| `Open` | `Actor(buyer, arbiter)`, signed by the buyer | The arbiter records the case, then opens the escrow job naming itself as the controller. |
| `Decide`, `Release` | `Actor(judge, arbiter)`, signed by the judge | The arbiter lets the provider claim part of the deposit. |
| `Decide`, `Return` | `Actor(judge, arbiter)`, signed by the judge | The arbiter gives what was never released back to the buyer. |

- The case lives in the arbiter's own case account, derived from the job account. It holds the escrow, the judge, the buyer, the provider and the job reference.
- `Open` derives the job from the buyer who signed, so nobody can record a case for someone else's job.
- The judge is checked at the case's actor, which only the arbiter itself can reach. A decision from anyone else fails whole, escrow call included.
- The judge has to call directly. LEZ carries a signature into every program call, so a program the judge signs for can't decide in the judge's name.
- On a controlled job, delivering releases nothing: the provider's `Deliver` only records the result for the judge to look at.

The program is [`src/lib.rs`](src/lib.rs), its zkVM entry point is in [`guest`](guest), and [`client`](client) is a small CLI that sends its calls for the walkthrough below. [`tests/arbiter.rs`](tests/arbiter.rs) covers every refusal, and the end of [`integration/tests/flows.rs`](../../integration/tests/flows.rs) runs the judge's whole flow on LEZ's state machine.

## What you need

- `logos-devnet` 0.10 or later, which runs LEZ `v0.4.0-rc3`, and Docker
- Rust, `jq`, and `cargo-risczero` 3.0 (`rzup install cargo-risczero 3.0.5`, `rzup install rust`)
- both programs built, from the repo root:

```bash
make build
```

## Run it

From this directory:

```bash
logos-devnet up
source .logos-devnet/env
export LEE_WALLET_HOME_DIR="$LOGOS_DEVNET_ACCOUNTS_PARTIES_WALLET"
buyer=$(jq -r '.accounts[0].id' "$LOGOS_DEVNET_ACCOUNTS_PARTIES")
provider=$(jq -r '.accounts[1].id' "$LOGOS_DEVNET_ACCOUNTS_PARTIES")
judge=$(jq -r '.accounts[2].id' "$LOGOS_DEVNET_ACCOUNTS_PARTIES")
job=$(openssl rand -hex 32)
arbiter() { cargo run -q -p logos_escrow_arbiter_client -- "$@" --buyer "$buyer" --job-ref "$job"; }
escrow() { cargo run -q -p logos_escrow_cli -- "$@" --buyer "$buyer" --job-ref "$job"; }
```

`logos-devnet.toml` here gives the example a devnet of its own on a free port, deploys the escrow and the arbiter from your build, and funds three accounts in one wallet: the buyer, the provider and the judge. `arbiter` sends the arbiter's calls, and `escrow` is the escrow's own CLI.

The buyer locks 1M lepta for 10 minutes, with the judge deciding:

```bash
arbiter open --judge "$judge" --provider "$provider" --pay-to "$provider" --refund-to "$buyer" --amount 1000000 --in-secs 600
# tx <hash> in block <n>
# job <job account>: Open, released 0, claimed 0
```

Before working on it, the provider checks the case: it exists, names the judge they expect, and the real escrow:

```bash
arbiter show
# judge <judge>
# job <job account>: Open, amount 1000000, released 0, claimed 0, pay_to <provider>, deadline <ms>
```

The provider delivers. The record shows the result, still `Open` with `released: 0`:

```bash
escrow deliver --result "$(printf 'the work' | shasum -a 256 | cut -d' ' -f1)"
```

The provider tries to judge in its own favour. The wallet runs the call first and doesn't send it, since the arbiter refuses it with `WrongJudge`:

```bash
arbiter release --judge "$provider" --amount 1000000
# Error: send failed: SimulatedRevert("Program exited with non-zero code 105 after <n> cycles")
```

The judge pays the provider 400k, and the provider claims it. The job account then holds 600k:

```bash
arbiter release --judge "$judge" --amount 400000
# job <job account>: Open, released 400000, claimed 0
escrow claim
```

The judge gives the rest back, and the buyer refunds it. The job account ends empty and `Refunded`:

```bash
arbiter return --judge "$judge"
# job <job account>: Returned, released 400000, claimed 400000
escrow refund
```

`logos-devnet up` takes about 20 s and the calls another 20 s, once `cargo` has built the two CLIs. `logos-devnet down` stops the devnet, and deleting `.logos-devnet` removes it.

## Before you take a job

- **Check the case.** A buyer can open a job straight on the escrow and still name the arbiter as its controller. That job has no case, and can never get one, so no judge can decide it and the buyer refunds everything after the deadline. `arbiter show` refuses such a job.
- **Check the escrow.** The arbiter calls whichever escrow a case names, with the judge's signature carried into that call. So a judge decides a case only when it names the real escrow, which `arbiter show` checks.
- **Check the deadline.** From then on the buyer can refund what was never released. The judge can still release after it, but only a release that lands before the refund counts. A delivery just before the deadline leaves the judge no time, so take a job only with time for the judge after the work is due.

## Use it in your project

Copy `src/lib.rs` and `guest/` into your project, and depend on the escrow's rules from this repo. Until the first 0.4 release, pin a commit:

```toml
logos_escrow_core = { git = "https://github.com/drptbl/logos-escrow", rev = "<commit>" }
```

- Build your guest in a crate of its own, as `guest/` here, and deploy it yourself.
- Bind whatever you record to the escrow's job, as `Open` does with `job_account_id`, and take decisions only from direct calls.
- Change who decides to fit your project: a committee, a deadline of your own, an oracle's account. The escrow only cares that the call comes from the controller its job names.

## Limits

- It has only run with public parties.
- A decision reaches the escrow through the party's own actor, so with a private buyer or provider it needs that party's witness, and an offline private party blocks it.
- The judge is an account with a key. A program can't be the judge, since decisions have to be direct calls.
- A judge that never decides leaves the buyer to refund what was never released after the deadline. Until that refund lands, the judge can still release.
