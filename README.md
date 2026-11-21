# logos-escrow

Job escrow for the Logos Execution Zone. A buyer locks a payment for one job and releases it to the provider in parts, or all at once when the provider delivers. The buyer gets back what was never released when the provider doesn't deliver by the deadline.

Built for agent services in [logos-mcp](https://github.com/drptbl/logos-mcp), but any LEZ wallet can call it, and other programs can build on it: a job can name a controller program, such as a marketplace, a DAO or an arbiter, that decides what the provider gets. Testnet only: LEZ is not meant for real funds yet.

## Status

Built for LEZ `v0.4.0-rc3`, the newest 0.4 release. It isn't deployed yet: there is no 0.4 testnet so far. Its program id goes here once there is.

For LEZ `v0.3`, use [release `v0.2.0`](https://github.com/drptbl/logos-escrow/releases/tag/v0.2.0), the last one that supports it, deployed on the v0.3 testnet as `H1VFAwgBoB8ECWQntzNVE7NpyFneVmtGFmZhJGwcT3sF`. Its [README](https://github.com/drptbl/logos-escrow/blob/v0.2.0/README.md) describes it.

Each release on GitHub carries the program binary, `logos_escrow.bin`, and its sha256 and image id, built from the release tag in CI with the command below, which reproduces it.

## How it works

Each job lives in its own job account. The account holds the locked lepta, as the native token's state, and the job record, as the escrow program's state.

The buyer names two payout addresses at `Open`: `pay_to`, where the provider is paid, and `refund_to`, where the deposit goes back. Money only ever moves there, and only when the side being paid asks for it: the provider pulls with `Claim`, the buyer with `Refund`. `Release` and `Return` move nothing. They only let the other side pull early. So nobody ever pays into someone else's address, which is what keeps private payout addresses safe.

| State | Reached by | Next |
| --- | --- | --- |
| `Open` | `Open` | `Delivered`, `Returned`, `Refunded` |
| `Delivered` | `Deliver`, on a job without a controller | final |
| `Returned` | `Return` | `Refunded` |
| `Refunded` | `Refund` | final |

The record also counts lepta: `released` is how much of `amount` the provider may take, and `claimed` how much it took. `Claim` works in any state, so whatever was released stays the provider's after a `Return` or a `Refund`.

- The provider delivers by recording a 32-byte result hash before the deadline, for example the SHA-256 of the result it sent. The chain can't check the result itself.
- On a job without a controller there are no disputes. Delivering releases everything left, and the buyer can no longer refund. On a controlled job, delivering releases nothing, see [Controllers](#controllers).
- The buyer can `Release` any part of what's left of an open job, as many times as it likes, and the provider can claim it without delivering.
- A provider that can't do an open job can `Return` it, and the buyer can then refund what was never released at once instead of waiting for the deadline.
- The buyer picks both payout addresses, so a provider should read the record and check `pay_to`, `amount`, `deadline` and `controller` before it works on a job.
- Deadlines are milliseconds since the Unix epoch, checked against the block's timestamp.
- The record stays after the job ends, so a job reference can't be used twice.
- There is no escrow fee. Whoever sends a transaction pays LEZ's fee for it.
- The job itself is public: anyone can read its record, amount and deadline.
- Payouts never move more than `amount` in total. Lepta that someone sends to a job account on top of it stay there for good.

## Controllers

A job can name a controller at `Open`, a program that acts on it besides the buyer and provider. It sends the escrow the same instruction a party would, to the party's actor, without the party's signature.

- The controller can `Release` any part of what's left and `Return` the job without the parties. Those are an arbiter's two decisions: pay the provider, or give the rest back.
- `Deliver`, `Claim` and `Refund` still need the party they name, even from the controller. So only the side being paid pulls a payout, and a controller can't pull one publicly to a private payout address, where it would be lost. A party that is the controller's own PDA signs through it, with the PDA's seed on the call.
- On a controlled job, delivering only records the result. The provider gets paid when the buyer or the controller releases.
- The parties keep their direct calls. The deadline still lets the buyer refund what was never released, so a stuck controller can't lock the money. The controller can still release after the deadline, but only a release that lands before the buyer's refund counts. So set a deadline that leaves it time after the work is due: a delivery just before the deadline leaves it none.
- A program can only act on jobs that name it. A program that opens a job has to name itself, and a call from any other program is refused with `NotDirect`.
- A party that is a program's PDA can only act through that program, so that program has to be the job's controller. Make a PDA provider for a job controlled by another program, or by none, and it can never deliver or claim: whatever was released to it stays in the job account.

The controller decides who gets the money, never where it goes: payouts only reach `pay_to` and `refund_to`. Read what the controller does, and whether it can be updated, before you open or take a controlled job.

A buyer can open a job directly and still name any controller. That suits a controller that keeps no state of its own, but one that keeps a record per job, as the example arbiter does with its cases, only works for jobs opened through it. A provider checks that record before starting work: a job with no record names a controller that can never decide it.

LEZ carries a signer's authorization into every program call, so a program you sign a transaction for can open a job with your lepta, just as it could transfer them. The controller rule protects your existing jobs, not a signature you give a hostile program.

[`examples/arbiter`](examples/arbiter) is a controller to start from, where a named judge decides each job.

## Job account

The job account is a public PDA of the escrow program:

```text
seed = SHA-256("/lez-escrow/v1/JobSeed/000000000" || buyer || job_ref)
job  = SHA-256("/LEE/v0.2/AccountId/PDA/" || 8 zero bytes || program_id || seed)
```

`buyer`, `job_ref` and `program_id` are 32 bytes each, and both prefixes are 32 bytes. The seed domain keeps the project's former name, lez-escrow, so callers' derivation code didn't change with the rename. Deriving from the buyer too means nobody who learns a `job_ref` can open that job first.

`core/tests/escrow.rs` (`the_job_account_and_instruction_layout_are_stable`) pins these against literals computed with Python's `hashlib`, so you can check your own derivation against it.

## Calling it

LEZ 0.4 delivers each message to an actor: one account's state under one program. A party sends its instruction to its own actor under the escrow, `Actor(party, escrow)`, signed by the party. A transaction also declares every public actor it touches, as below. `job` means `Actor(job, escrow)`, and `native(x)` the native token's actor on `x`, which holds its lepta.

| Instruction | Sent to | Declares | Allowed when | Moves |
| --- | --- | --- | --- | --- |
| `Open` | `Actor(buyer, escrow)` | `job`, `native(buyer)`, `native(job)` | before `deadline`, job account empty | `amount` from buyer to job |
| `Deliver` | `Actor(provider, escrow)` | `job` | before `deadline`, `Open`, once | nothing |
| `Claim` | `Actor(provider, escrow)` | `job`, `native(job)`, `native(pay_to)` | any state, `amount` up to `released - claimed` | `amount` from job to `pay_to` |
| `Release` | `Actor(buyer, escrow)` | `job` | `Open`, `amount` up to `amount - released` | nothing |
| `Refund` | `Actor(buyer, escrow)` | `job`, `native(job)`, `native(refund_to)` | `Open` from `deadline` on, or `Returned` | `amount - released` from job to `refund_to` |
| `Return` | `Actor(provider, escrow)` | `job` | `Open` | nothing |

LEZ admits a public account the chain has never seen into a transaction only with its public key as evidence. So a `Claim` or `Refund` to a fresh public `pay_to` or `refund_to` carries that account's key. The side being paid sends the call, so it has it.

Name every party, payee and controller by its canonical account id. LEZ resolves a private sender's blinded alias to its real account before delivery, so a job that recorded an alias would never match its party's calls.

Each instruction also carries the values the record must match, and the call fails when they don't. Read the record first: `Deliver` quotes its `deadline`, a `Claim` takes at most `released - claimed`, and a `Refund` exactly `amount - released`. A `Refund` after a `Return` passes `deadline` 0, because the deadline no longer applies.

`lez_core` has no 0.4 release yet. Until then, `integration/tests/flows.rs` builds every one of these transactions, signed and declared as above, and runs it through LEZ's own state machine.

### Instruction data

Borsh: one variant byte, then the fields in order. Integers are little-endian, an account id or hash is 32 raw bytes, and an `Option` is `0`, or `1` and the value.

| Byte 0 | Instruction | Fields | Length |
| --- | --- | --- | --- |
| `0` | `Open` | `job_ref: [u8; 32]`, `provider: [u8; 32]`, `pay_to: [u8; 32]`, `refund_to: [u8; 32]`, `amount: u128`, `deadline: u64`, `controller: Option<[u8; 32]>` | 154, or 186 with a controller |
| `1` | `Deliver` | `buyer: [u8; 32]`, `job_ref: [u8; 32]`, `result: [u8; 32]`, `deadline: u64` | 105 |
| `2` | `Claim` | `buyer: [u8; 32]`, `job_ref: [u8; 32]`, `amount: u128` | 81 |
| `3` | `Release` | `job_ref: [u8; 32]`, `amount: u128` | 49 |
| `4` | `Refund` | `job_ref: [u8; 32]`, `amount: u128`, `deadline: u64` | 57 |
| `5` | `Return` | `buyer: [u8; 32]`, `job_ref: [u8; 32]` | 65 |

`Deliver { buyer: [1; 32], job_ref: [9; 32], result: [4; 32], deadline: 1800000000000 }` encodes to:

```text
01 0101010101010101010101010101010101010101010101010101010101010101
   0909090909090909090909090909090909090909090909090909090909090909
   0404040404040404040404040404040404040404040404040404040404040404 00505c18a3010000
```

## Reading a job

The record is the escrow's state on the job account, `Actor(job, escrow)`, and there is no job while it's empty. The locked lepta are the native token's state on the same account, a 16-byte little-endian `u128`, empty at zero.

The record is Borsh:

| Field | Type |
| --- | --- |
| `buyer` | `[u8; 32]` |
| `provider` | `[u8; 32]` |
| `pay_to` | `[u8; 32]` |
| `refund_to` | `[u8; 32]` |
| `amount` | `u128` |
| `released` | `u128` |
| `claimed` | `u128` |
| `deadline` | `u64`, milliseconds |
| `state` | `u8`: `0` Open, `1` Delivered, `2` Returned, `3` Refunded |
| `result` | `Option<[u8; 32]>` |
| `controller` | `Option<[u8; 32]>` |

`core/tests/escrow.rs` (`the_job_record_and_controlled_open_layout_are_stable`) pins a whole record against a literal.

Read the counters to tell whether a job is settled, rather than `state`: a job released in full and claimed stays `Open`. Nothing is left to pay once `claimed` equals `released` and either `released` equals `amount` or the job is `Refunded`.

## Private accounts

The job stays public, but buyer and provider can be private accounts, and so can the payout addresses. Make each payout address a fresh private account for that one job, under the keys of whoever gets paid: the provider sends its `pay_to` with the quote, and the buyer picks its own `refund_to`.

Never pull to a private address in a public call. The program can't tell the two apart, so the money would land in a public account with that id, and nobody can sign for that.

On LEZ 0.4 this hasn't run on a chain yet: private transactions there pay fees, and private account ids are derived differently than on v0.3. The rules don't change, and the tests cover them with public parties.

## Errors

The program refuses a call by exiting with one of these codes, and LEZ then charges only the cycles used. A refused public call is still included and pays for those cycles, so read the record again to see whether a call worked.

| Code | Error | Means |
| --- | --- | --- |
| 1 | `InvalidInstruction` | the message doesn't decode |
| 2 | `Unauthorized` | the party the instruction names didn't authorize it |
| 3 | `WrongJobAccount` | the job account isn't the one derived from buyer and `job_ref` |
| 4 | `JobExists` | `Open` on a job account that already has a record |
| 5 | `InvalidTerms` | `Open` with a zero amount, the buyer as provider, or the job account as a payout address |
| 6 | `WrongParty` | the party isn't the job's buyer or provider as the instruction needs |
| 7 | `WrongDeadline` | `deadline` isn't the job's |
| 8 | `NoJob` | no record in the job account |
| 9 | `WrongState` | the job isn't in a state this instruction takes |
| 10 | `WrongAmount` | `amount` is zero, more than a `Release` or `Claim` may move, or not what a `Refund` returns |
| 11 | `NotDirect` | a program other than the job's controller called the escrow, or a program opened a job without naming itself |

LEZ itself refuses the rest, so check the deadline, the declared actors and the buyer's balance before you send:

- `OutOfValidityWindow`: an `Open` or `Deliver` at or after the deadline, or a `Refund` before it on a job that wasn't returned
- `NativeTransferFailed`: an `Open` the buyer can't fund
- `UndeclaredActor`, `UnadmittedPublicActor`: a transaction that doesn't declare an actor it touches, or pays a fresh public account without its key

## CLI

`cli/` still runs on LEZ v0.3's wallet, so it isn't part of the 0.4 build. It comes back with a 0.4 wallet and a 0.4 chain to test against. For v0.3, use the one in release `v0.2.0`.

## Build and test

You need Rust, Docker and the RISC Zero toolchain (`rzup install cargo-risczero 3.0.5`, `rzup install r0vm 3.0.5`, `rzup install rust`).

```bash
make build
make test
```

`make build` builds the guest in RISC Zero's Docker image `r0.1.91.1`, the one LEZ `v0.4.0-rc3` builds its own programs with, so the image id is reproducible. `methods/guest/Cargo.lock` is part of that identity too: change it and the image id changes. `make test` runs the program's rules as plain Rust, then the built binary through LEZ `v0.4.0-rc3`'s state machine with real signatures, declared actors, program calls and deadlines. CI runs both.

`make build` also builds the [example arbiter](examples/arbiter), from its own guest crate so the escrow's image id never depends on it. Next to the escrow it builds `test_controller.bin`, a test-only program that relays whatever escrow call it gets, so the tests can call the escrow from another program. It checks nothing, so never deploy it anywhere that matters.

## License

MIT ([LICENSE-MIT](LICENSE-MIT)) or Apache 2.0 ([LICENSE-APACHE](LICENSE-APACHE)).
