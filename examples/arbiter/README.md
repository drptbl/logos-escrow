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

The program is [`src/lib.rs`](src/lib.rs) and its zkVM entry point is in [`guest`](guest). [`tests/arbiter.rs`](tests/arbiter.rs) covers every refusal, and the end of [`integration/tests/flows.rs`](../../integration/tests/flows.rs) runs the judge's whole flow on LEZ `v0.4.0-rc3`'s state machine, with both programs built:

```bash
make build
cargo test -p logos_escrow_integration
```

A walkthrough on a local chain comes back once logos-devnet runs LEZ 0.4. [`client`](client), the small CLI it used, still runs on v0.3's wallet.

## Before you take a job

- **Check the case.** A buyer can open a job straight on the escrow and still name the arbiter as its controller. That job has no case, and can never get one, so no judge can decide it and the buyer refunds everything after the deadline. Read the arbiter's state on the case account first: it has to exist, and name the judge you expect.
- **Check the escrow.** The arbiter calls whichever escrow a case names, with the judge's signature carried into that call. So a judge decides a case only when it names the real escrow.
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
