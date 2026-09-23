---
author: Dat Ho
pubDatetime: 2026-09-23T00:00:00Z
title: 'Envelope encryption, part 2: what someone with database access can make the vault do'
description: "A security review of the multi-tenant secret vault from part 1 asked what happens when the attacker is already inside the database, or when there is more than one app instance. I wrote the tests before touching the code. Seven of nine failed, and two of my fixes were wrong the first time."
tags: [security, cryptography, dotnet, event-sourcing, aws, testing]
featured: false
draft: false
---

[Part 1](/posts/envelope-encryption-multi-tenant-secrets) ended on the claim that everything difficult
about the vault lived around the cryptography rather than in it: where bytes are allowed to rest, how
long a key lives in memory, what "deleted" means. A security reviewer read it and, fairly politely,
agreed with that sentence and then pointed out how much of it I had not actually tested.

The adversarial tests in part 1 asked one question: what leaks out of the API? The response shape,
the error bodies, a tampered ciphertext. The review asked a different one. What can someone make
the vault do if they already have write access to the database? And what happens when there is more
than one instance of the app, each with its own idea of the current key?

Before changing any code I wrote those tests and ran them against the version described in part 1.
Nine new tests. Seven failed. Most of them were things the reviewer had asked about directly, and
the review was right about every one. Two were on nobody's list: a document id that two tenants could
share, and an audit trail that lost most of its entries under concurrent reads. And one of the failures
had been sitting in a function I quoted approvingly in the first post.

This is what they found, what I changed, and the two fixes I got wrong before getting them right.

## Table of contents

## One tenant reading another's secret

The first test is the one the reviewer called mandatory, and it is almost boring. Tenant A stores a
secret. Tenant B, who has a vault of its own, asks for it by name. B has to get a 404. It did. The
document lookup includes the tenant id, so B's request looks for B's row and finds nothing.

That passed, and it would have been easy to stop there. What made me keep going was the function that
builds the document id, which I had been reading to write that test:

```csharp
public static string BuildId(string tenantId, string name) => $"{tenantId}:{name}";
```

Tenant `acme` with a secret called `x:y` gets the id `acme:x:y`. So does tenant `acme:x` with a secret
called `y`. Nothing stopped a tenant id from containing a colon, and the route took it as given.

The test for it creates the victim, stores `x:y`, and then acts as tenant `acme:x`. Reading `y` did not
leak anything, which is worth being precise about. The attacker's request found the victim's row,
tried to decrypt it with the attacker's own DEK, and the authentication tag failed. Per-tenant keys did
exactly the job part 1 said they would. Writing was a different story. A PUT from `acme:x` for `y`
stored a document under `acme:x:y`, replacing the victim's row with ciphertext under the attacker's
key. The victim's next read failed. Their secret was gone, and nothing in the API would have told
them why.

The reviewer put the invariant as "the tenant from the authenticated identity equals the tenant used
in every database predicate, not merely the controller checks tenant once". This bug satisfied the
letter of that and still broke it, because the predicate was a string that two different tenants could
produce. The fix is dull: tenant ids may not contain a colon, every endpoint rejects one with a 400,
and the read checks the row's own tenant and name fields as well as its id. Hold onto the shape of
the mistake, though, because it comes back in the next section.

## The tag authenticates the bytes, not where they sit

Part 1 made a fair amount of the GCM authentication tag. Corrupt a byte and decryption throws, so a
damaged secret fails loudly instead of reaching a payment provider as garbage. All of that is still
true. The review's strongest technical point was about what the tag does not cover.

It covers the ciphertext. It says nothing about which row the ciphertext is in. The test copies secret
X's nonce, ciphertext and tag onto secret Y's row, same tenant:

```sql
UPDATE encrypted_secrets AS target
SET data = target.data
    || jsonb_build_object('Nonce', source.data->'Nonce', 'Ciphertext', source.data->'Ciphertext', 'Tag', source.data->'Tag')
FROM encrypted_secrets AS source
WHERE source.id = @from AND target.id = @to
```

Then it reads Y. The response was a 200, carrying X's value. Same tenant, same DEK, a perfectly
intact ciphertext, so the tag checked out. Picture that with real names. Your staging database
password comes back when you ask for the production one, and nothing anywhere logs an error.

The cross-tenant version is worse. Swapping only the wrapped DEK between two tenants failed closed:
tenant A ends up with B's key, A's ciphertext does not authenticate under it, and the read errors out.
That test passed on the old code. But copy tenant A's wrapped DEK *and* A's ciphertext into tenant B's
rows, and B now has a matching key and ciphertext pair. B read A's secret with a 200. Per-tenant keys
only separate tenants as long as the key and the data stay where they were put, and someone with
database write access can move both.

AES-GCM has a slot for exactly this, associated data: bytes that are not encrypted but are covered by
the tag. Decryption only succeeds if the caller supplies the same associated data that was used to
encrypt. So the cipher now takes a binding, the tenant, the secret name, and which write of that secret
this is:

```csharp
private static byte[] AssociatedData(int formatVersion, SecretBinding binding)
{
    switch (formatVersion)
    {
        case LegacyFormatVersion:
            return [];
        case CurrentFormatVersion:
            using (var stream = new MemoryStream())
            {
                WriteField(stream, AadDomain);
                WriteInt(stream, formatVersion);
                WriteField(stream, Encoding.UTF8.GetBytes(binding.TenantId));
                WriteField(stream, Encoding.UTF8.GetBytes(binding.Name));
                WriteInt(stream, binding.Version);
                return stream.ToArray();
            }
        default:
            throw new CryptographicException($"Unknown secret format version {formatVersion}");
    }
}
```

Every field is length-prefixed, and that is the colon bug paying its rent. The obvious way to build
this is to join the fields with a separator, which is the document id mistake over again: tenant `a:b`
plus name `c` and tenant `a` plus name `b:c` would produce identical bytes, and each would
authenticate the other's ciphertext. Having just found that bug in the ids, I was not going to write
it a second time. There is a unit test for that exact pair now.

Now the moved ciphertext is read under Y's binding, the tag no longer matches, and the read fails. The
transplant into tenant B is read under B's tenant id and fails the same way. Neither of these replaces
the tenant predicate in the query. They are there for the day the predicate is wrong, which the
previous section showed is not a hypothetical.

### Rows written before any of this existed

Every secret already stored was encrypted with no associated data at all, and adding a binding to the
decrypt call would make every one of them fail. So each row now records a format version. Version 0 is
the old shape and decrypts with empty associated data; version 1 is the binding above. New writes are
always version 1. A forced rotation, which already decrypts and re-encrypts every row a tenant owns,
rewrites them in the new format on the way through, so it doubles as the migration.

The obvious attack on that arrangement is to relabel a new row as version 0 and skip the check. It
fails, because the format version is itself inside the associated data. A version 1 ciphertext does
not authenticate under an empty binding. What does remain open, and I would rather say it than have it
found: two *legacy* rows in the same tenant can still be swapped with each other, because neither has a
binding to fail. That gap closes for a tenant on its first forced rotation, and not before.

## Replay, and the event stream earns its place again

Binding a ciphertext to its tenant and name stops it moving sideways. The review raised a third
direction: backwards in time. Store a value, overwrite it, then restore the old row. The test does
precisely that, saving the whole row as JSON after the first write and putting it back after the
second. The old code served the old value with a 200.

Putting the secret's version into the associated data is necessary but, on its own, not enough. The
attacker restores the entire old row, version number included, so the old ciphertext is read under the
old version and authenticates perfectly. The row is internally consistent. It is just not current, and
nothing inside the row can know that.

Something outside the row has to. This is where part 1's storage split, the one I got wrong first,
turns out to have been more useful than I knew. Secret values moved out of the event stream into
mutable rows so they could be deleted. The stream kept only metadata: that a write happened, and when.
It is append-only, so it is also the one place an attacker with a row-level `UPDATE` cannot quietly
rewind. So the write event now carries the secret's version, the vault aggregate keeps the latest
version per name, and a read refuses any row that disagrees with it:

```csharp
// The document is mutable and the stream isn't. An older row restored over this one
// would still decrypt (its AAD matches its own version), so the stream has the last word.
if (doc.Version != vault.SecretVersions.GetValueOrDefault(name))
{
    throw new CryptographicException("Stored secret does not match the vault's record of it");
}
```

An attacker who can rewrite the event stream as well defeats this, of course. That is a much bigger
ask than rewriting one row, and the stream is where you would be looking for evidence anyway.

This is also where the review's point about versioning lands. It argued that the post treated three
different things as one: which KMS key material wraps the DEK, which DEK the tenant is on, and which
version of a secret's value is stored. It was right, and the code had the same blur. The vault tracked
the first and nothing else. Now it tracks all three, and they move independently. A rewrap changes
the key material and nothing else. A forced rotation changes the DEK. A write changes one secret's
version. When someone asks, during an incident, which secrets were written under the DEK you think is
compromised, the stream can now answer.

One thing I deliberately did not build is value history. A write still replaces the row, and the old
value is gone. Versions exist to detect replay and to make those relationships explicit, not to let
anyone read last month's password. Keeping history would have undone the whole reason the values left
the log.

## The cache key that a rotation did not change

The review's biggest concern was the plaintext DEK cache, and my own notes going into this said the
fix would be a paragraph in part 1 admitting that eviction is per-process. It turned out to be a bug
rather than a caveat.

Part 1 describes the cache as keyed by tenant and key version, and it presents the eviction logic as
the careful part: cancel a per-tenant token and the old plaintext key is gone immediately, rather than
sitting in memory for the rest of its five minutes. On one instance that is true. The reviewer's point
was that with two instances, instance A's eviction reaches instance A's memory and nowhere else.

Follow that through. Instance B reads a secret and caches tenant T's DEK under the key
`(T, key version M)`. An admin on instance A force-rotates T: new DEK, every row re-encrypted. A forced
rotation mints a new data key, but under the same KMS master key, so the key version is still M. Then
a write for T lands on instance B. B reads the vault, sees key version M, finds its cached DEK under
exactly the key it expects, and encrypts the new secret with the DEK that was just retired.

The write returns 204. Nothing looks wrong. Five minutes later B's cache entry expires, and from then on
that secret cannot be decrypted by anyone, because the vault no longer holds the key it was written
under. The test simulates B by putting the old DEK back into the cache under its old key after a
rotation, then writing. On the old code the read that follows failed.

So the reviewer's framing, that a revoked key stays usable on the other instance, was right, and the
consequence was worse than it sounded. Not just a key that should be dead still decrypting things, but
a key that should be dead encrypting new things, invisibly, until they became unreadable.

The fix is to key the cache on what actually identifies the plaintext: which of the tenant's DEKs this
is. The vault aggregate now counts DEKs, one at provisioning and one more per forced rotation, derived
from the stream rather than stored anywhere it could disagree with it. After a rotation, B looks up
`(T, DEK 2)`, misses, and unwraps the current key from KMS. A side effect I did not see coming: a
rewrap no longer needs to touch the cache at all, because rewrapping changes the wrapping and not the
plaintext, and the cache no longer cares about the wrapping.

What this does not fix is the reviewer's original concern in its pure form. Instance B still holds the
retired DEK in memory until its TTL runs out. It will never use it again, but a heap dump taken in that
window has it. The review listed the questions a production deployment should answer around that: who
can take a memory dump, whether crash reporting or APM tooling can capture heap contents, whether
anything logs key material, whether revocation needs to propagate between instances synchronously.
None of those have answers in this codebase, because this codebase is a component and not a
deployment. They are the right questions, and five minutes is still the guess part 1 admitted it was.

## A rewrap that undid a rotation

The review's concurrency section asked whether a stale write can overwrite a newer wrapped DEK. My
notes from reading it said the framework's optimistic concurrency on the aggregate might already
prevent it, and not to claim either way until I had checked. Checking took one test, and the answer
was no.

The lazy rewrap in part 1 happened in two halves. The read endpoint noticed the wrapping was stale,
called KMS to rewrap the DEK, and then handed the result to a separate message handler, as a command,
to append the `DekRewrapped` event. That split existed so the read endpoint could stay a read. The
command looked like this:

```csharp
public record RecordSecretAccess(
    string TenantId,
    string Name,
    bool NeedsRewrap,
    byte[]? RewrappedDek,
    string? RewrappedKeyVersionId);
```

It carries key material, computed at the moment of the read. Now suppose a forced rotation commits
between the read and the handler. The handler loads the vault, which now holds the new DEK, and
appends the rewrapped *old* DEK on top of it. The optimistic concurrency check passes, because it
compares the stream version against what the handler itself just loaded, and the handler loaded the
vault after the rotation. The version check was protecting the wrong read.

The result is a vault whose wrapped DEK is the one the rotation retired, sitting over rows that the
rotation re-encrypted under the new one. Every secret in the tenant becomes unreadable at once. The
test replays that sequence by sending the command by hand after a rotation, and on the old code the
tenant's secret came back as a 500.

The reviewer suggested a compare-and-swap guarded on the previous key version. I went a step further
and took the key material out of the command entirely:

```csharp
public record RecordSecretAccess(string TenantId, string Name, bool LooksStale);
```

The read now reports only what it saw: "this looked stale". The handler re-checks staleness against
the vault as it is when the handler runs, and if it is still stale, it does the KMS rewrap itself. A
decision made on current state cannot be stale by construction, which beats guarding a decision made
on old state.

## A hundred readers, and the audit trail I had overclaimed

The last concurrency question in the review was whether a hundred concurrent reads after a rotation
all call KMS. The test does exactly that: rotate the master key, fire a hundred reads for one tenant,
wait for everything to settle, count. I expected an embarrassing number of KMS calls. I did not expect
the other number.

Two runs on the old code:

- 100 KMS rewrap calls, 37 `DekRewrapped` events, 36 access events recorded
- 98 KMS rewrap calls, 37 `DekRewrapped` events, 36 access events recorded

The KMS figure was the one I was looking for, and it was as bad as predicted: every stale read did its
own rewrap. Thirty-seven rewrap events is wasteful but harmless, since they all wrap the same DEK. The
number that stopped me was the last one. A hundred reads, and thirty-six of them in the audit trail.

Every read appends to the tenant's one stream. A hundred handlers raced to append, lost the stream's
concurrency check to each other, retried, lost again, ran out of retries, and were dropped. Part 1
said that with the vault event sourced, "every write, every read, every rotation arrives timestamped
and in order, without anyone writing audit logging code". Under concurrent reads, roughly two-thirds of
the reads never arrived. For a component whose argument for event sourcing was the audit trail, that
is the sentence in part 1 I would most like back.

The re-check from the previous section helped less than I hoped. With it in place and nothing else,
the same test gave 15 KMS calls and 1 rewrap event, but still only 38 and then 52 of the hundred reads
recorded. The handlers were still racing each other for the stream. The re-check just meant fewer of
the losers had called KMS before losing.

What fixed it was making one tenant's access records run one at a time. The messages are now routed
through a queue partitioned by tenant id, so any two access records for the same tenant are processed
in order, across the cluster, while different tenants still run in parallel. With that, five runs in a
row gave the same result: 1 KMS call, 1 rewrap event, 100 access events. The first handler finds the
vault stale and rewraps it. The other ninety-nine find it fresh and only record the read.

## Fixing the write race, twice

The concurrency work turned up one more race that was on nobody's list, and it is the one I needed
two attempts at.

A write reads the vault, gets the DEK, encrypts, and commits. A forced rotation reads every row,
re-encrypts them all under a new DEK, and commits. If the rotation commits while a write is between its
read and its commit, the write lands a row encrypted under the retired DEK. It is the multi-instance
cache bug again, arrived at from a different direction, and the outcome is the same: a 204, then a
secret nobody can read.

My first fix was the textbook one. Read the vault with an expected version, so the write's append
fails if anything else committed to the stream first. A write that loses a race with a rotation gets
refused instead of silently corrupting a row. Correct, and tests stayed green.

To check it I wrote a randomised test, five rounds of twenty concurrent writes fired alongside a
rotation, asserting that every acknowledged write stayed readable. I then ran the same test against
the *original* code, to see it fail. It passed, three times out of three. The window between a write's
read and its commit is small, and firing requests at it and hoping had not hit it once. And on the new
code it reported something else: 95 of the 100 writes had been refused.

That is what the optimistic check does when every write for a tenant appends to the same stream. It
does not just refuse writes that race a rotation. It refuses writes that race each other, and a burst
of writes to twenty *different* secrets is exactly that. I had fixed a data-loss bug by making
concurrent writes mostly fail.

Both problems needed a test that could hit the window deliberately. The fake KMS used in the test
suite got a gate: the next unwrap call parks until the test releases it. The test clears the cache so
the write has to unwrap, starts the write, waits until it is parked (vault read, nothing written yet),
runs a rotation in that gap, then releases the write:

```csharp
public async Task<byte[]> UnwrapAsync(byte[] wrappedDek, CancellationToken cancellationToken)
{
    if (Interlocked.Exchange(ref _unwrapGate, null) is { } gate)
    {
        gate.Reached.SetResult();
        await gate.Release.Task.WaitAsync(cancellationToken);
    }

    return Unwrap(wrappedDek);
}
```

The first version of that timed out, and it took me longer than I would like to admit to see why. I had
stored the gate as a nullable tuple, and swapping a struct with `Interlocked.Exchange` throws at run
time. The write crashed before it ever reached the gate, and the test sat there waiting for a signal
that was never coming. It was my own test harness again, the same category of mistake as the tamper
test in part 1 that passed without testing anything.

With the gate fixed, the test did its job. On the original code: write acknowledged with a 204, then a
500 on read. On the optimistic fix: the write refused with a 500, which is safe but useless under load.

The second fix was to make writers wait for each other instead of failing. A write, a rotation, and
the access-record handler now each take a row lock on the tenant's stream record when they load the
vault, held until they commit. A write that arrives during a rotation queues behind it, then reads the
new DEK. Twenty writes to different secrets queue behind each other and all succeed.

That has a cost, and the test suite found it before I had finished writing it down. The first version
of the burst test fired a hundred concurrent writes at one tenant, and four of them failed with
`53300: sorry, too many clients already`. A writer waiting on a row lock is holding a database
connection while it waits, and a hundred of them ran the database out of connections before the lock
itself became the bottleneck. At thirty concurrent writes, all thirty succeed. So the honest summary is
that one tenant's writes are now serial, including the KMS unwrap on a cache miss, and a burst of
writes to one tenant costs a connection each. For a secrets vault, where reads vastly outnumber writes,
I think that is the right trade. It is a trade, though, and the first design was not free of it
either; it just paid in refused writes instead.

## What is still open

Some of the review I could not act on, and it is better written here than discovered.

The reviewer wanted a test proving that an attacker's credentials cannot be used to read another
tenant's secrets by changing the route. That test cannot be written against this component, because
it has no authentication to test. Part 1 was explicit that the tenant id is supposed to come from a
validated token in the hosting application. The review's phrasing of the gap stuck with me: do not only
test the component's assumption, test the seam where the assumption becomes real. That test belongs
to whatever hosts this vault, and it should exist before anything real is stored in it.

KMS can bind a wrapped data key to a context, the same idea as associated data one level up, so that a
wrapped DEK only unwraps when you present the tenant id it was created for. The vault does not use it.
Associated data on the secrets now catches the whole-row transplant between tenants, but binding the
wrapped DEK as well would catch it at KMS, before any plaintext key reaches the application.

Legacy rows keep their weaker guarantee until each tenant's first forced rotation, as covered above.
And the plaintext DEK cache is still a five-minute window of memory exposure per instance, with the
operational questions around it unanswered.

## What I would tell myself before part 1

**An authentication tag covers bytes, not locations.** I understood GCM's tag as "this ciphertext is
intact" and stopped there. Intact and in the right place are different properties, and only the first
comes for free. If a ciphertext can be moved between rows by anyone, what it belongs to has to be part
of what gets authenticated.

**Any string built by joining identifiers is a collision waiting for input.** It was already in the
document ids, and the associated data is the obvious next place to repeat it. Length-prefix
the fields, or forbid the separator, and write the test with the colliding pair in it.

**Key a cache by what identifies the value, not by something that usually changes with it.** The key
version changed on most rotations. It did not change on the one kind of rotation that matters most, and
the cache happily served a retired key under an unchanged name.

**Do not carry decisions across a queue, carry observations.** The rewrap command held a DEK computed
at read time and applied it at some later time. The version check on the handler guarded the handler's
own read and nothing else. Sending "this looked stale" and letting the handler decide on current state
removed the race rather than guarding it.

**Run the new test against the old code before trusting it.** The randomised race test passed against
the code it was written to catch. If I had only run it after the fix, it would have been one more
green check proving nothing, and the 95 refused writes would have gone unnoticed too.

**An audit trail is a claim about concurrency.** "Every read is recorded" was true one request at a
time. It stopped being true at a hundred, and I only found out because the reviewer asked about KMS
calls and I happened to count the other events as well.

The vault's cryptography did not change much in all of this: one extra argument to one function. Every
failure the tests found was in the same place part 1 said the difficulty lived, around the cipher
rather than in it. Part 1 described those questions. It turns out I had not asked most of them with
two instances, a hundred readers, or an attacker already in the database.

## References

- NIST, [SP 800-38D: Recommendation for GCM](https://csrc.nist.gov/pubs/sp/800/38/d/final):
  the definition of additional authenticated data in GCM.
- AWS, [Encryption context](https://docs.aws.amazon.com/kms/latest/developerguide/encrypt_context.html):
  binding KMS ciphertext, including wrapped data keys, to non-secret context.
- PostgreSQL, [Explicit locking: row-level locks](https://www.postgresql.org/docs/current/explicit-locking.html#LOCKING-ROWS):
  row-level lock modes, including the `FOR UPDATE` lock the exclusive load takes on the stream record.
- PostgreSQL, [Connections and authentication: max_connections](https://www.postgresql.org/docs/current/runtime-config-connection.html#GUC-MAX-CONNECTIONS):
  the limit the hundred-writer burst ran into.
