---
name: logos-escrow
description: Integrate the logos-escrow job escrow on the Logos Execution Zone (LEZ v0.4). Use when paying or getting paid for a job through escrow from a client, building a controller program (marketplace, DAO, arbiter) that settles escrow jobs, or testing a project against the escrow.
---

# logos-escrow

[README.md](../../README.md) is the interface reference: status, actors to send to and declare, instruction and record layouts, error codes. Read the section a step names before you encode anything. This skill holds the order of work and the rules integrations get wrong. It targets LEZ 0.4; for v0.3 use release `v0.2.0` and its README.

## Settle a job from a client

1. Take the program id of a deployment (README, Status), or of your own deploy of the released binary.
2. Derive the job account from the buyer and a 32-byte `job_ref` (README, Job account). A `job_ref` is spent for that buyer once opened, so make each one fresh.
3. Before every call after `Open`, read the job record (README, Reading a job) and quote it: `Deliver` takes the record's `deadline`, `Claim` at most `released - claimed`, and `Refund` exactly `amount - released`, with `deadline` 0 after a `Return`.
4. Send the call to the party's own actor `Actor(party, escrow)`, signed by that party, declaring every actor the README's table lists for it (README, Calling it).
5. Read the record again to learn the outcome. The wallet runs a call before sending it and reports a refusal's code, but a call sent anyway is included and charged, so inclusion alone proves nothing. Done when the record shows the state and counters you expected.

The repo's CLI (README, CLI) does all of this over the LEZ wallet, and is the quickest reference for a working call.

Rules every call keeps:

- The side being paid pulls its own payout, and it always goes to the record's `pay_to` or `refund_to`. To pay a public account the chain has never seen, add that account's public key as admission evidence; the LEZ wallet adds it for the accounts it holds.
- Give each account one identity per transaction: the LEZ wallet refuses one named both signing and not, so a signer paid to itself keeps its signer's identity on its balance too.
- Pay a private call's fee from a funded private account the wallet owns: private transactions pay in the proof, about 5M lepta each on a `v0.4.0-rc3` devnet.
- Name every party, payee and controller by its canonical account id, never a blinded alias: LEZ resolves an alias before delivery, so a job that recorded one never matches its party.
- Pull to a private payout address only from a private call (README, Private accounts). A public pull lands the money in a public account nobody can sign for.
- Deadlines are milliseconds since the Unix epoch, checked against the block's timestamp: `Open` and `Deliver` land before it, a deadline `Refund` at or after it.
- As a provider, read `pay_to`, `amount`, `deadline` and `controller` from the record before you start the work. On a controlled job, also read the controller's own record for the job, such as the example arbiter's case: a buyer can open a job directly and name a controller that keeps no record of it, and so can never decide it. Take the job only with time for the controller between the work being due and the deadline, when the buyer can refund what was never released.
- Tell a settled job by its counters, never by `state` alone: nothing is left once `claimed` equals `released` and either `released` equals `amount` or the job is `Refunded`.

## Build a controller program

Start from [examples/arbiter](../../examples/arbiter/README.md): what it does, what a provider and a judge check, and how to copy it into your project. Then hold to these, which the README's Controllers section explains:

- Your program opens the job itself and names its own program id as `controller`. The escrow refuses a program that names anything else.
- Your program alone may `Release` and `Return` without the parties, by sending the instruction to the party's actor under the escrow. `Deliver`, `Claim` and `Refund` stay with the party they name, or with your program's PDA when you send its seed with the call.
- Take a signer's call at its own actor under your program, where `is_authorized` says it signed. Keep your state on PDA actors of your own, send to them with the PDA's seed so LEZ admits a fresh one, and accept their messages only when `from_own_program()` holds.
- Take a decision only from a direct call (`from` is `None`). LEZ carries a signature into every program call, so otherwise any program your decider signs for could decide in their name.
- Pass identities in your own messages, not through `from.account_id`: a private sender shows up there under a blinded alias.
- Bind your own state to the escrow's job, deriving the job with `job_account_id(escrow, buyer, job_ref)` from the buyer who signed, so nobody records first for someone else's job.
- Refuse by exiting with a code: LEZ charges an exit only for the cycles used, and a panic for the whole budget. Any refusal fails the whole transaction, escrow call included.
- A party that is a program's PDA acts only through that program, so that program must be the job's controller.
- Build your guest in its own crate. A guest sharing the escrow's crate changes the escrow's image id, and the build no longer matches the deployed program.

## Test against the escrow

1. Build the escrow with `make build`, and add its binary to your `logos-devnet.toml` (README, On your own devnet). logos-devnet 0.10 and later run LEZ `v0.4.0-rc3`.
2. Run `logos-devnet up`, then your tests under `logos-devnet exec -- <command>`, which exports `LOGOS_PROGRAM_ESCROW` and the chain's other settings.
3. Give every run fresh `job_ref`s. A devnet keeps its state between runs, so run `logos-devnet reset` before a test that recreates the same private accounts.

For tests without a chain, run the real guests through LEZ's own state machine, as `integration/tests/flows.rs` does: seed a `V03State` from the `lee` crate (feature `test-utils`) with the programs at fixed ids, and send signed transactions that declare their actors and carry admission evidence for fresh payees.
