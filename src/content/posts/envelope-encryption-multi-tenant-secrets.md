---
author: Dat Ho
pubDatetime: 2026-09-22T00:00:00Z
title: 'Envelope encryption for multi-tenant secrets: the parts nobody draws on the whiteboard'
description: "Per-tenant data keys wrapped by a KMS master key, lazy rewrap on read, forced rotation, and the storage decision I got wrong the first time. A walkthrough of an actual implementation, including what the adversarial tests found and the one feature I decided not to build."
tags: [security, cryptography, dotnet, event-sourcing, aws]
featured: true
draft: false
---

Storing a tenant's API keys and database passwords feels finished the moment the ciphertext lands
in the database. It isn't. Encrypting a value is the easy half of this problem, and it is the half
most write-ups stop at.

The hard half arrives later. Keys have lifetimes. Somebody eventually rotates the one you encrypted
everything under. A customer's credentials leak and they want to know you can re-key their data
without touching anyone else's. Someone asks you to delete one secret, permanently, and expects a
straight answer. None of those are cryptography questions. Every one of them is a question about
key lifecycle and storage, and that is where the real design work turns out to be.

Envelope encryption is the standard answer, and it usually gets explained in two sentences:
encrypt the data with a data key, encrypt the data key with a master key, done. That is true, and
it is nowhere near enough to build from. It leaves every interesting decision still open. How do
you find out that the master key moved? What does a read cost you when it did? Where does the
ciphertext physically sit, and can you ever actually delete it?

What follows is how those got answered in a real multi-tenant secret vault, including the one I
answered wrong and had to tear back out.

## Table of contents

## Two keys, because one key has no exit

Start with the naive shape and watch where it breaks. One key, every secret encrypted under it.
Nothing about that is insecure. The cryptography is perfectly sound. The problem is that it has no
exit.

Picture the day you have to rotate it. Every encrypted byte you own has to be decrypted and
re-encrypted, all of it, in a single operation. If that operation dies halfway through, you now own
two populations of ciphertext under two different keys and nothing in the schema tells you which
row belongs to which. You cannot do it gradually either, because the design has no way to
distinguish data you have already migrated from data you have not. One key means one enormous,
all-or-nothing, unresumable migration, forever.

So you split the job in two:

- A **master key** that lives in a KMS (AWS KMS here) and never leaves it. The application cannot
  read it, only ask KMS to perform operations with it.
- A **data encryption key** (DEK) per tenant, AES-256, which actually encrypts secret values.
  It lives in plaintext only in process memory, and is persisted only in wrapped form, encrypted
  by the master key.

Now rotating the master key touches one wrapped blob per tenant, each of them around 32 bytes, and
the secrets underneath never move at all. The enormous migration became a rounding error.

None of this is a clever local invention. It is the shape both major clouds converged on, for the
reason you would expect. Azure's
[data encryption at rest](https://learn.microsoft.com/en-us/azure/security/fundamentals/encryption-atrest)
documentation calls the outer key a key encryption key and states the tradeoff plainly:

> Azure encryption at rest models use envelope encryption, where a KEK encrypts a data encryption
> key (DEK). [...] Limiting the use of a single encryption key decreases the risk that the key is
> compromised and the cost of re-encryption when a key must be replaced.
>
> <cite>Microsoft, [Azure data encryption at rest](https://learn.microsoft.com/en-us/azure/security/fundamentals/encryption-atrest)</cite>

That last clause is the whole design compressed into one sentence. Both the risk of compromise and
the cost of re-encryption scale with how much data sits under a single key, so you arrange things
so that almost nothing sits under the outer one.

Per tenant rather than one DEK for everyone is the same argument applied a second time. If a DEK is
somehow exposed, the damage stops at that tenant's data. It also turns "this customer thinks they
were breached, re-key their secrets today" from an apology into an operation you can actually
perform.

<figure>
<svg viewBox="0 0 720 300" role="img" aria-labelledby="envelope-title" xmlns="http://www.w3.org/2000/svg" style="width:100%;height:auto;color:inherit">
  <title id="envelope-title">The master key wraps a per-tenant data key, which encrypts the secret value</title>
  <defs>
    <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M 0 0 L 10 5 L 0 10 z" fill="currentColor" />
    </marker>
  </defs>
  <g fill="none" stroke="currentColor" stroke-width="1.5">
    <rect x="16" y="24" width="210" height="96" rx="8" opacity="0.85" />
    <rect x="266" y="24" width="210" height="96" rx="8" opacity="0.85" />
    <rect x="516" y="24" width="188" height="96" rx="8" opacity="0.85" />
    <rect x="266" y="186" width="210" height="82" rx="8" stroke-dasharray="5 4" opacity="0.6" />
    <rect x="516" y="186" width="188" height="82" rx="8" stroke-dasharray="5 4" opacity="0.6" />
  </g>
  <g fill="currentColor" font-family="ui-monospace, monospace" font-size="13">
    <text x="32" y="50" font-weight="600">KMS master key</text>
    <text x="282" y="50" font-weight="600">Per-tenant DEK</text>
    <text x="532" y="50" font-weight="600">Secret value</text>
  </g>
  <g fill="currentColor" font-family="ui-sans-serif, system-ui" font-size="12" opacity="0.75">
    <text x="32" y="74">Never leaves KMS.</text>
    <text x="32" y="92">The app holds no copy</text>
    <text x="32" y="110">and cannot export it.</text>
    <text x="282" y="74">AES-256, minted by KMS.</text>
    <text x="282" y="92">Plaintext in memory only,</text>
    <text x="282" y="110">persisted wrapped.</text>
    <text x="532" y="74">AES-256-GCM.</text>
    <text x="532" y="92">Random nonce per write,</text>
    <text x="532" y="110">plus an auth tag.</text>
    <text x="282" y="212">WrappedDek + KeyVersionId</text>
    <text x="282" y="232">on the tenant's event</text>
    <text x="282" y="252">stream. Safe to persist.</text>
    <text x="532" y="212">Nonce, Ciphertext, Tag</text>
    <text x="532" y="232">in a plain document row.</text>
    <text x="532" y="252">Deletable.</text>
  </g>
  <g fill="none" stroke="currentColor" stroke-width="1.5" marker-end="url(#arrow)">
    <path d="M 230 72 L 260 72" />
    <path d="M 480 72 L 510 72" />
  </g>
  <g fill="none" stroke="currentColor" stroke-width="1.5" stroke-dasharray="4 4" marker-end="url(#arrow)" opacity="0.6">
    <path d="M 371 124 L 371 182" />
    <path d="M 610 124 L 610 182" />
  </g>
  <g fill="currentColor" font-family="ui-sans-serif, system-ui" font-size="11" opacity="0.7" text-anchor="middle">
    <text x="245" y="64">wraps</text>
    <text x="495" y="64">encrypts</text>
    <text x="371" y="150">stored as</text>
    <text x="610" y="150">stored as</text>
  </g>
</svg>
<figcaption>Two keys, two storage locations, and only one of them ever holds a secret value.</figcaption>
</figure>

Everything the application is allowed to ask of the master key fits in four methods, which is worth
showing because the shape of this interface is the whole security boundary. Nothing above it knows
that AWS is on the other side, and nothing above it can get its hands on the master key:

```csharp
public interface IMasterKeyService
{
    /// <summary>Mint a new DEK, wrapped by the current master key material.</summary>
    Task<DataKey> GenerateDataKeyAsync(CancellationToken cancellationToken);

    /// <summary>Unwrap a DEK. Works regardless of which key material originally wrapped it.</summary>
    Task<byte[]> UnwrapAsync(byte[] wrappedDek, CancellationToken cancellationToken);

    /// <summary>Re-wrap an existing DEK under the current master key material.</summary>
    Task<RewrappedDek> RewrapAsync(byte[] wrappedDek, CancellationToken cancellationToken);

    /// <summary>The identifier of the master key material currently used for wrapping.</summary>
    Task<string> GetCurrentKeyVersionAsync(CancellationToken cancellationToken);
}
```

Three of those are unremarkable. `RewrapAsync` is the one that makes the whole rotation story
possible, and it is worth understanding why. It maps to KMS
[`ReEncrypt`](https://docs.aws.amazon.com/kms/latest/APIReference/API_ReEncrypt.html), which the
API reference describes as:

> Decrypts ciphertext and then reencrypts it entirely within AWS KMS. You can use this operation to
> change the KMS key under which data is encrypted, such as when you manually rotate a KMS key or
> change the KMS key that protects a ciphertext.
>
> <cite>AWS, [KMS API Reference: ReEncrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_ReEncrypt.html)</cite>

"Entirely within AWS KMS" is the load-bearing phrase. The wrapped DEK moves onto current key
material without the plaintext DEK ever coming back across the network to me. Without that one
operation, responding to a master key rotation would mean pulling every tenant's plaintext key into
application memory just to hand it straight back, which is a spectacularly bad few seconds to have
a heap dump.

## The cipher, and why the authentication tag earns its keep

That covers the outer key. The inner one does the actual work, and the code for it is small enough
to read in one sitting: it takes a plaintext DEK and a string, and performs authenticated
encryption.

```csharp
public static EncryptedPayload Encrypt(byte[] plaintextDek, string plaintext)
{
    var nonce = RandomNumberGenerator.GetBytes(NonceSizeBytes);
    var plaintextBytes = System.Text.Encoding.UTF8.GetBytes(plaintext);
    var ciphertext = new byte[plaintextBytes.Length];
    var tag = new byte[TagSizeBytes];

    using var aesGcm = new AesGcm(plaintextDek, TagSizeBytes);
    aesGcm.Encrypt(nonce, plaintextBytes, ciphertext, tag);

    return new EncryptedPayload { Nonce = nonce, Ciphertext = ciphertext, Tag = tag };
}
```

GCM rather than plain CBC comes down to that `tag` variable, and the difference it makes is larger
than it looks. Corrupt a stored CBC ciphertext, whether through an attacker or an ordinary bug, and
decryption cheerfully produces garbage. Garbage is the dangerous outcome, because an application
has no way to recognise it. It will return that garbage to a caller, who will send it to a payment
provider as an API key. GCM's tag makes that impossible: if a single byte moved, `Decrypt` throws,
and the request fails. A failed read is an incident you find out about in the logs. A silently wrong
read is one you find out about from your payment provider.

The other line to notice is the nonce, freshly random on every encryption. It means encrypting the
same value twice yields completely different ciphertext both times. Someone who steals the entire
table cannot tell which tenants share a password, or whether the value stored today matches the one
from last year. That property costs nothing here and it is easy to take for granted, so hold onto
it. There is a popular feature later in this post that quietly throws it away.

## Where the ciphertext lives, and the version I had to undo

The vault is event sourced, one stream per tenant. That choice was made for the audit trail, and it
pays off immediately: every write, every read, every rotation arrives timestamped and in order,
without anyone writing audit logging code. For a component whose entire job is guarding credentials,
being able to answer "who touched this, and when" is close to a requirement.

So the first version put the secrets in the stream too. The `SecretStored` event carried the nonce,
the ciphertext and the tag. One store, one source of truth, beautifully tidy.

It took me embarrassingly long to notice what I had done.

Append-only means append-only. That is not a limitation of any particular event store, it is the
entire proposition: the log is trustworthy precisely because nothing can be taken back out of it.
Which is wonderful for an audit trail, and catastrophic for the thing I had just put inside one.

The bill arrives the first time somebody asks you to delete a secret. Someone always does. An
employee leaves and their token has to go, a customer offboards and invokes a retention clause, a
regulator asks what "delete" means on your platform. With ciphertext in the log, the honest answer
is that you cannot. The archive operation an event store gives you marks a stream as closed, it does
not remove anything. Backups and write-ahead logs keep their copies regardless of what the
application thinks it deleted. You can of course reach past the framework and issue a raw `DELETE`
against the events table, but at that point you are not using event sourcing any more, you are
vandalising it, and any projection or replay that depended on that stream is now quietly wrong.

The fix was to stop asking the log to do a job it was never designed for, and split storage by
lifetime instead:

<figure>
<svg viewBox="0 0 720 330" role="img" aria-labelledby="storage-title" xmlns="http://www.w3.org/2000/svg" style="width:100%;height:auto;color:inherit">
  <title id="storage-title">Before, ciphertext lived in the append-only event stream; after, it lives in a deletable document</title>
  <g fill="currentColor" font-family="ui-sans-serif, system-ui" font-size="13" font-weight="600">
    <text x="16" y="22">Before</text>
    <text x="16" y="192">After</text>
  </g>
  <g fill="none" stroke="currentColor" stroke-width="1.5">
    <rect x="16" y="36" width="160" height="58" rx="6" opacity="0.85" />
    <rect x="186" y="36" width="190" height="58" rx="6" opacity="0.85" />
    <rect x="386" y="36" width="190" height="58" rx="6" opacity="0.85" />
    <rect x="16" y="206" width="160" height="58" rx="6" opacity="0.85" />
    <rect x="186" y="206" width="190" height="58" rx="6" opacity="0.85" />
    <rect x="386" y="206" width="190" height="58" rx="6" opacity="0.85" />
    <rect x="386" y="278" width="310" height="44" rx="6" stroke-dasharray="5 4" opacity="0.7" />
  </g>
  <g fill="currentColor" font-family="ui-monospace, monospace" font-size="11">
    <text x="30" y="60">VaultProvisioned</text>
    <text x="200" y="60">SecretStored</text>
    <text x="400" y="60">SecretStored</text>
    <text x="30" y="230">VaultProvisioned</text>
    <text x="200" y="230">SecretStored</text>
    <text x="400" y="230">SecretAccessed</text>
    <text x="400" y="300">EncryptedSecretDocument</text>
  </g>
  <g fill="currentColor" font-family="ui-sans-serif, system-ui" font-size="11" opacity="0.75">
    <text x="30" y="80">WrappedDek</text>
    <text x="200" y="80">Name + Nonce + Ciphertext</text>
    <text x="400" y="80">Name + Nonce + Ciphertext</text>
    <text x="30" y="250">WrappedDek</text>
    <text x="200" y="250">Name + timestamp</text>
    <text x="400" y="250">Name + timestamp</text>
    <text x="400" y="317">one row per (tenant, name), mutable, deletable</text>
  </g>
  <g fill="none" stroke="currentColor" stroke-width="1.5" opacity="0.8">
    <path d="M 176 65 L 186 65" />
    <path d="M 376 65 L 386 65" />
    <path d="M 176 235 L 186 235" />
    <path d="M 376 235 L 386 235" />
    <path d="M 576 65 L 600 65" stroke-dasharray="3 3" />
    <path d="M 576 235 L 600 235" stroke-dasharray="3 3" />
  </g>
  <g fill="currentColor" font-family="ui-sans-serif, system-ui" font-size="12">
    <text x="16" y="124" opacity="0.9">Append-only. The ciphertext is now permanent,</text>
    <text x="16" y="142" opacity="0.9">so "delete this secret" can never be honoured.</text>
    <text x="16" y="294" opacity="0.9">Stream is audit only: nothing in it ever</text>
    <text x="16" y="312" opacity="0.9">needs to be un-said, so it can live forever.</text>
  </g>
</svg>
<figcaption>The redesign: metadata in the log, secret material in a row you can actually drop.</figcaption>
</figure>

After the change, `SecretStored` carries a name and a timestamp and nothing else. The ciphertext
moved to an ordinary mutable row, one per tenant and secret name, deleted the way you delete any
row. The aggregate kept only the key bookkeeping, which was never secret material in the first
place:

```csharp
public class TenantSecretVault
{
    public required string Id { get; set; }
    public required byte[] WrappedDek { get; set; }
    public required string KeyVersionId { get; set; }
    public required DateTimeOffset WrappedAt { get; set; }
    // ...
}
```

At this point a reasonable objection turns up, and it is one I had to think about properly before
committing to the redesign: envelope encryption already hands you a delete primitive. Throw away the
key and the ciphertext becomes noise. Azure names this directly:

> Because decrypting the DEKs requires the KEK, you can cryptographically erase DEKs and data by
> disabling the KEK.
>
> <cite>Microsoft, [Azure data encryption at rest](https://learn.microsoft.com/en-us/azure/security/fundamentals/encryption-atrest)</cite>

All true, and it still does not rescue the original design, because cryptographic erasure only works
at the granularity of a key. Destroying key material erases everything that key protected. The
request that actually shows up is "delete this one secret and keep the other forty for this tenant",
and that is a row-level operation. No amount of key management performs it. You would need a key per
secret to make erasure that precise, at which point you have reinvented per-row storage with extra
steps and a much worse failure mode.

So the rule I took away, and the one I would lead with if I were designing this again: an
append-only log is the right home for statements that stay true forever, and a secret value is not
one of those. "Tenant X wrote a secret named `stripe-key` at 14:02" is true permanently, and nothing
will ever require you to un-say it. The value of that key is true only until someone rotates it, and
may have to be erasable on demand. Two different lifetimes, therefore two different places to put
them. I found that boundary by putting it in the wrong place first.

## Two kinds of rotation, because they cost wildly different amounts

Storage settled, the question the master key raised at the start comes back around: it moved, so now
what happens to every DEK wrapped under the old material?

The trap here is that this sounds like one operation. It is two, they differ in cost by several
orders of magnitude, and wiring them together is how you accidentally build the thing envelope
encryption was supposed to prevent.

**Lazy rewrap on read** is the cheap one, and it covers the ordinary case. The master key rotated,
so the DEK's *wrapping* is out of date. Note what is not out of date: the DEK itself, and every
secret ever encrypted under it. Nothing about that data is less safe than it was yesterday. So on
the next read for that tenant, ask KMS to re-encrypt the wrapped DEK, record a `DekRewrapped` event,
carry on. One small call, one small event, no secret value touched.

**Forced rotation** is the expensive one, and it exists for a genuinely different situation: you
believe the DEK itself is compromised. Now the data really is at risk, and nothing short of new
ciphertext fixes it. A fresh DEK is minted and every secret the tenant owns is decrypted under the
old key and re-encrypted under the new one, in one transaction:

```csharp
foreach (var doc in documents)
{
    var plaintextValue = SecretCipher.Decrypt(oldPlaintextDek, new EncryptedPayload
    {
        Nonce = doc.Nonce, Ciphertext = doc.Ciphertext, Tag = doc.Tag
    });

    var payload = SecretCipher.Encrypt(newDataKey.PlaintextDek, plaintextValue);

    doc.Nonce = payload.Nonce;
    doc.Ciphertext = payload.Ciphertext;
    doc.Tag = payload.Tag;
    Save(doc);

    events += new SecretReencrypted { Name = doc.Name, ReencryptedAt = now };
}
```

That is an O(n) write, sitting behind an admin endpoint where a human has to ask for it. It is the
right response to a suspected compromise or a compliance-driven crypto-period limit. It is entirely
the wrong response to a routine master key rotation, and the temptation to connect the two is real,
because from a distance both of them look like "the key changed, re-key the data". Give in to that
and every scheduled rotation triggers a full re-encryption of every tenant's data, on a schedule,
forever. Which is the exact cost envelope encryption exists to avoid, now reintroduced by
automation.

## The staleness check, and the thing AWS makes annoying

Lazy rewrap has an obvious prerequisite I have been quietly skipping over: to rewrap on a stale
read, you have to be able to tell that the wrapping is stale. This turned out to be the fiddliest
corner of the entire design, and the one I got least right.

If rotation is managed by repointing an alias at a new key, detection is trivial. Resolve the alias,
compare the resulting ARN against the key version recorded on the aggregate, flag a mismatch as
stale. That is all `GetCurrentKeyVersionAsync` does.

Then you turn on AWS's automatic rotation and the whole approach quietly stops working.

Automatic rotation replaces the backing key material underneath you while keeping the same key ARN,
which the
[rotation documentation](https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html)
is explicit about:

> The KMS key is the same logical resource, regardless of whether or how many times its key material
> changes. The properties of the KMS key do not change.
>
> <cite>AWS, [Rotate AWS KMS keys](https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html)</cite>

Identical before, identical after. The comparison does not fail, which would at least be honest. It
succeeds, reports everything as current, and rewraps nothing, for as long as automatic rotation
stays enabled. So the implementation falls back to the only signal it believed it had, which is the
clock:

```csharp
private static async Task<bool> IsStaleAsync(
    TenantSecretVault vault,
    IMasterKeyService masterKeyService,
    KmsOptions options,
    CancellationToken cancellationToken)
{
    var currentKeyVersion = await masterKeyService.GetCurrentKeyVersionAsync(cancellationToken);

    // Manual/alias-based rotation: the resolved key version changed outright.
    if (currentKeyVersion != vault.KeyVersionId)
    {
        return true;
    }

    // AWS KMS automatic rotation: same ARN, key material rotated transparently - fall
    // back to a time-based staleness window.
    return DateTimeOffset.UtcNow - vault.WrappedAt > options.AutomaticRotationFallbackWindow;
}
```

The fallback window defaults to 180 days, which is half of the default rotation period. AWS's
default is 365 days, and it is configurable rather than fixed:

> Rotation period defines the number of days after you enable automatic key rotation that AWS KMS
> will rotate your key material [...] If you do not specify a value for `RotationPeriodInDays` when
> you enable automatic key rotation, the default value is 365 days.
>
> <cite>AWS, [Rotate AWS KMS keys](https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html)</cite>

There is the first crack in the 180 day constant. It is tuned to a default that whoever administers
the key can change to 90 days on a Tuesday afternoon without telling me, and nothing anywhere in
this code would notice or complain.

The second crack is considerably worse, and in the interest of honesty: I found it while writing
this post, not while building the thing. My entire justification for falling back to a timer was
that rotated key material has no identifier exposed through the API, leaving nothing to compare
against. That is simply not true, and it has a name. KMS returns a `KeyMaterialId`, on the very
operations this code already calls.
[`GenerateDataKey`](https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKey.html)
returns one alongside the data key, and
[`ReEncrypt`](https://docs.aws.amazon.com/kms/latest/APIReference/API_ReEncrypt.html) returns both
`SourceKeyMaterialId` and `DestinationKeyMaterialId`:

> **SourceKeyMaterialId**: The identifier of the key material used to originally encrypt the data.
> [...] **DestinationKeyMaterialId**: The identifier of the key material used to reencrypt the data.
>
> <cite>AWS, [KMS API Reference: ReEncrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_ReEncrypt.html)</cite>

There is also [`ListKeyRotations`](https://docs.aws.amazon.com/kms/latest/APIReference/API_ListKeyRotations.html),
which returns a `KeyMaterialId` and `RotationDate` per completed rotation, and an EventBridge
`KMS CMK Rotation` event plus a CloudTrail `RotateKey` entry on every rotation.

So the correct design was sitting in the response payload the whole time. Store the `KeyMaterialId`
that comes back from `GenerateDataKey` instead of, or alongside, the key ARN, and compare that on
read. It is an exact signal for precisely the case the heuristic was invented to paper over. It
costs no extra API call, because the value arrives on a call already being made. And it would let
the entire `AutomaticRotationFallbackWindow` option, its default, and the paragraph of documentation
justifying it all be deleted.

That is the first thing I would change if I picked this up again, and it is a better outcome than
the timer deserved.

One more thing worth pinning down before leaving rotation, because it explains why both paths have
to exist at all. AWS is blunt about what rotating the master key does not do:

> Key rotation has no effect on the data that the KMS key protects. It does not rotate the data keys
> that the KMS key generated or re-encrypt any data protected by the KMS key. Key rotation will not
> mitigate the effect of a compromised data key.
>
> <cite>AWS, [Rotate AWS KMS keys](https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html)</cite>

Read that last sentence twice if you are tempted to treat scheduled rotation as a security control.
Rotating the master key is hygiene and compliance, and it is cheap precisely because it changes
nothing about your data. A compromised data key is a different incident with a different answer, and
that answer is the expensive re-encryption sitting behind the admin endpoint. Two problems, two
tools, and the whole rotation design falls out of refusing to conflate them.

<figure>
<svg viewBox="0 0 720 340" role="img" aria-labelledby="read-title" xmlns="http://www.w3.org/2000/svg" style="width:100%;height:auto;color:inherit">
  <title id="read-title">Read path: cache lookup, optional KMS unwrap, decrypt, staleness check, optional lazy rewrap</title>
  <defs>
    <marker id="arrow2" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M 0 0 L 10 5 L 0 10 z" fill="currentColor" />
    </marker>
  </defs>
  <g fill="none" stroke="currentColor" stroke-width="1.5">
    <rect x="16" y="20" width="132" height="48" rx="6" opacity="0.85" />
    <rect x="16" y="108" width="132" height="48" rx="6" opacity="0.85" />
    <rect x="216" y="108" width="150" height="48" rx="6" stroke-dasharray="5 4" opacity="0.7" />
    <rect x="16" y="196" width="132" height="48" rx="6" opacity="0.85" />
    <rect x="216" y="196" width="150" height="48" rx="6" opacity="0.85" />
    <rect x="434" y="196" width="150" height="48" rx="6" stroke-dasharray="5 4" opacity="0.7" />
    <rect x="434" y="278" width="270" height="48" rx="6" stroke-dasharray="5 4" opacity="0.7" />
  </g>
  <g fill="currentColor" font-family="ui-monospace, monospace" font-size="12">
    <text x="30" y="42">GET secret</text>
    <text x="30" y="130">DEK in cache?</text>
    <text x="230" y="130">KMS Decrypt</text>
    <text x="30" y="218">AES-GCM decrypt</text>
    <text x="230" y="218">stale wrapping?</text>
    <text x="448" y="218">KMS ReEncrypt</text>
    <text x="448" y="300">append DekRewrapped</text>
  </g>
  <g fill="currentColor" font-family="ui-sans-serif, system-ui" font-size="11" opacity="0.75">
    <text x="30" y="58">tenant + name</text>
    <text x="30" y="146">keyed by key version</text>
    <text x="230" y="146">only on a cache miss</text>
    <text x="30" y="234">fails closed on a bad tag</text>
    <text x="230" y="234">version compare, then age</text>
    <text x="448" y="234">wrapping only, not the DEK</text>
    <text x="448" y="316">evict cache, re-cache under new version</text>
  </g>
  <g fill="none" stroke="currentColor" stroke-width="1.5" marker-end="url(#arrow2)">
    <path d="M 82 72 L 82 104" />
    <path d="M 82 160 L 82 192" />
    <path d="M 152 132 L 212 132" />
    <path d="M 291 160 L 291 192" />
    <path d="M 152 220 L 212 220" />
  </g>
  <g fill="none" stroke="currentColor" stroke-width="1.5" marker-end="url(#arrow2)" stroke-dasharray="4 4" opacity="0.7">
    <path d="M 370 220 L 430 220" />
    <path d="M 509 248 L 509 274" />
  </g>
  <g fill="currentColor" font-family="ui-sans-serif, system-ui" font-size="11" opacity="0.7">
    <text x="156" y="126">miss</text>
    <text x="374" y="214">yes</text>
    <text x="156" y="214">then</text>
  </g>
</svg>
<figcaption>A read on the happy path touches KMS zero times. A stale read costs one ReEncrypt, not a re-encryption.</figcaption>
</figure>

## Keeping KMS off the hot path

Everything described so far is correct and, implemented literally, quietly terrible. Trace a single
secret read through it: unwrap the DEK, which is a billed network round trip to KMS, then check
staleness, which is a second billed network round trip to KMS. Two calls per read, on every read,
both of them overwhelmingly likely to return exactly what they returned a second ago. Multiply by
your read volume and the lazy rewrap design has managed to be more expensive than the eager
re-encryption it replaced.

Two caches fix it. They look similar and they exist for completely different reasons, which is worth
separating.

The first caches the plaintext DEK, keyed by tenant and key version, with a five minute TTL.
Repeated reads for the same tenant inside that window never touch KMS at all. The cache itself is
unremarkable. The eviction is where the thought went. Keying by key version is not sufficient on its
own, because after a rewrap the stale entry is not wrong, merely orphaned, and it would sit there
holding a plaintext key in memory until its TTL happened to lapse. That is the one thing you do not
want lying around. So each tenant's entries hang off a cancellation token, and `Evict` cancels it to
force them out immediately:

```csharp
public void Set(string tenantId, string keyVersionId, byte[] plaintextDek)
{
    var tokenSource = _tenantTokens.GetOrAdd(tenantId, static _ => new CancellationTokenSource());

    using var entry = cache.CreateEntry(CacheKey(tenantId, keyVersionId));
    entry.Value = plaintextDek;
    entry.AbsoluteExpirationRelativeToNow = _ttl;
    entry.AddExpirationToken(new CancellationChangeToken(tokenSource.Token));
}
```

Both the rewrap path and the forced rotation path call `Evict` then `Set`, so a rotation drops
the old plaintext DEK immediately rather than leaving it live for the remainder of its TTL.

This cache is a deliberate departure from what AWS tells you to do. The `GenerateDataKey` reference
says, twice, to get rid of the plaintext key the moment you are done with it:

> Use this data key to encrypt your data outside of KMS. Then, remove it from memory as soon as
> possible.
>
> <cite>AWS, [KMS API Reference: GenerateDataKey](https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKey.html)</cite>

I am keeping it for up to five minutes instead, so let me not dress that up. A plaintext DEK sitting
in process memory is exposed to a memory disclosure bug, a heap dump, or anyone who can read the
process, for every second it stays there. What I bought with that exposure is not having to call KMS
on every read. That is a trade, not a free optimisation, and the word "cache" makes it sound more
innocent than it is.

Azure, running the same pattern at a rather larger scale, treats local DEK caching as ordinary:

> When services cache DEKs locally for active cryptographic operations, Azure platform security
> controls protect the cached keys [...] Cached operational keys are an availability and performance
> mechanism, the KEK in Key Vault remains the root of trust, and key revocation governs access to
> encrypted data.
>
> <cite>Microsoft, [Azure data encryption at rest](https://learn.microsoft.com/en-us/azure/security/fundamentals/encryption-atrest)</cite>

Neither party is wrong. They are pricing different risks for different threat models, and AWS is
writing guidance for everyone while Azure is describing a platform it controls end to end. The
useful way to hold it: that TTL is a dial between KMS spend and memory exposure window. Five minutes
is a guess. I did not measure it, nothing forced the number, and anyone running this in anger should
set it on purpose rather than inheriting my guess.

The second cache is narrower and exists for a slightly embarrassing reason. It wraps the key service
and caches exactly one thing, the current key version, letting generate, unwrap and rewrap pass
straight through untouched. It has to exist because the staleness check runs on every read, so
without it the *check* becomes a billed KMS call on every read. The optimisation would have paid for
itself and then charged you for the privilege. It is a small piece of code whose entire job is
stopping the design from defeating itself.

## Testing it like someone who wants to break it

Round-trip unit tests on the cipher are table stakes and prove very little: of course a value
survives encrypt then decrypt. The layer that earned its keep was a set of adversarial tests run
against a fully hosted instance of the app, real database, same dependency graph and middleware as
production, doing the things an attacker would actually try. Three of them are worth showing.

The first asserts on the exact shape of the read response. Over-exposure is rarely a bug someone
writes deliberately; it is what happens eight months later when a refactor starts serialising a
whole aggregate and nobody notices the wrapped key riding along with it:

```csharp
var propertyNames = json.EnumerateObject().Select(p => p.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);
propertyNames.ShouldBe(["name", "value"], ignoreOrder: true);

raw.ShouldNotContain("WrappedDek");
raw.ShouldNotContain("Ciphertext");
raw.ShouldNotContain("Nonce");
raw.ShouldNotContain("KeyVersionId");
```

The second forces an error path using a tenant id full of SQL-injection-shaped characters, then
asserts the response body contains no stack trace, no exception type names, and no database driver
strings. It is checking that a failure tells an attacker nothing about what is behind the endpoint.

The third is the one I would keep if I were only allowed one. It ignores the application completely,
opens its own database connection, and corrupts the stored ciphertext in place:

```sql
UPDATE encrypted_secrets
SET data = jsonb_set(data, '{Ciphertext}', to_jsonb('AAAAAAAAAAAAAAAA'::text))
WHERE id = @docId
```

Then it reads that secret back through the API and asserts the response is anything but success.
This is the authentication tag from way back in the cipher section, finally being made to prove
itself against a real database instead of being assumed from the fact that we picked an AEAD mode.
Choosing GCM is a claim. This is the evidence.

It is also where I hit the most instructive bug of the whole exercise. The first version of this
test performed its tampering through the application's own database session, which does not commit
until the unit of work is saved. The read that followed ran on a separate connection under read
committed isolation, so it never saw the corruption at all. Everything passed. The test was
green, confident, and verifying absolutely nothing.

Hence the standalone auto-committing connection, and hence an assertion that the tamper itself
affected exactly one row. That second part is the real lesson: the setup of a security test deserves
assertions as much as its conclusion does, because a tamper that silently matches zero rows produces
a passing test that means nothing at all. These tests are written so that red means a genuine
finding, which is what makes them worth re-running in CI forever rather than filing as a report that
was true once.

Two gaps I would rather state than have someone find. All of this ran against an in-memory stand-in
for KMS rather than the real thing, because the local emulator needs a Docker socket that was not
available, which means IAM policy correctness and real rotation behaviour against an actual key are
untested. And authentication is not part of this component at all: the tenant id is expected to
arrive from a validated JWT claim in the hosting application, never trusted from the route.

That second one is a scoping decision rather than an oversight, but it is only a scoping decision
because it is written down, in the docs, in the test file, and now here. An unauthenticated secrets
endpoint that nobody ever documented as somebody else's job is not a boundary. It is a vulnerability
with good intentions.

## The feature I decided not to build

A product we were comparing against listed searchable encryption as a feature, and on a feature list
it is unarguable. Search encrypted fields, never expose plaintext. Who would say no to that?

The usual implementation is a blind index: alongside the ciphertext you store
`HMAC-SHA256(indexKey, plaintextValue)` in a plain, indexed column, and you query on that instead.
It works, and it works because HMAC is deterministic. Same input, same key, same output, every time.

Which is the property I asked you to hold onto back in the cipher section, arriving now to be
demolished. Random nonces meant two identical secrets produced two unrelated ciphertexts, so a
stolen table revealed no relationships. A blind index hands that determinism straight back, in a
column, indexed for fast lookup, sitting next to the data it describes. Two tenants who chose the
same password now have visibly identical index values. Anyone holding the table and the index key
can work offline against a low-entropy field for as long as they like, with an index purpose-built
to make their comparisons fast.

So the feature reopens precisely the exposure that random nonces and rotation were put there to
close, and the thing it buys in return is query convenience that nobody had actually asked for.
Secrets here are looked up by name, and the name was never the sensitive part. No requirement, no
feature.

Elsewhere in the system there is a genuine need to search an encrypted field, and there the blind
index does exist, scoped to that one field, with the tradeoff written down beside it. That is the
distinction worth keeping: not "blind indexes are bad", but that a technique which weakens a
guarantee needs a requirement behind it, not a competitor's feature list.

## What I would tell myself at the start

Five things, roughly in the order they cost me time.

**Decide what "delete" means before you choose storage.** This is the one that cost the most,
because I had to build the wrong thing first to see it. An append-only log and a secret value have
fundamentally incompatible lifetimes, and no amount of cleverness reconciles them afterwards.
"What happens when somebody asks us to erase this" is not a feature to schedule for later. It is a
storage architecture question, and it belongs in the first conversation.

**Separate rotating the wrapping from rotating the key.** On a whiteboard they are the same arrow.
In production one is a single small call and the other rewrites every row a tenant owns. Nearly
every good decision in the rotation design came from refusing to let those two share a code path.

**Budget for the checks, not just the work.** Lazy rewrap was designed to avoid expensive
operations, and then very nearly cost more than what it replaced, because the staleness *check* ran
on every single read. Anything on a per-request path is a hot path, including the cheap-sounding
thing you added to avoid an expensive one.

**Read the whole API reference before engineering around its limits.** The 180 day window exists
only because I concluded that rotated key material had no observable identifier. It has one. It
arrives in a response the code was already reading. Compensating for a genuinely missing API is
sound engineering. Compensating for an API you did not finish reading is a bug with a configuration
option bolted to it, and it will look completely reasonable in review.

**Write the adversarial tests so they can actually fail.** Mine caught a transaction isolation
mistake in its own setup, which is exactly the sort of thing that turns a security suite into
decoration. A test that cannot fail is worse than no test at all, because no test is honest about
what it does not know, while a green check mark makes a promise somebody downstream will believe.

None of these are really about cryptography, which is the part that surprised me least by the end.
AES-GCM did its job the whole way through without complaint. Everything that was actually difficult
lived in the questions around it: where bytes are allowed to rest, how long a key is allowed to live
in memory, who is permitted to ask for what, and what your system means when it says a thing has
been deleted.

## References

Everything quoted above, in case you want to check my reading of it rather than take my word for it.

- AWS, [Rotate AWS KMS keys](https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html):
  rotation periods, the key ARN staying constant across rotations, and what rotation does not do.
- AWS, [KMS API Reference: GenerateDataKey](https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKey.html):
  the data key pattern, the `KeyMaterialId` response field, and the guidance on erasing plaintext keys.
- AWS, [KMS API Reference: ReEncrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_ReEncrypt.html):
  re-encryption entirely within KMS, and the source and destination key material identifiers.
- AWS, [KMS API Reference: ListKeyRotations](https://docs.aws.amazon.com/kms/latest/APIReference/API_ListKeyRotations.html):
  completed rotations with key material ids and rotation dates.
- Microsoft, [Azure data encryption at rest](https://learn.microsoft.com/en-us/azure/security/fundamentals/encryption-atrest):
  the KEK and DEK hierarchy, cryptographic erasure, and locally cached data encryption keys.
- PostgreSQL, [Transaction isolation](https://www.postgresql.org/docs/current/transaction-iso.html):
  read committed behaviour, which is what made the first version of the tamper test pass while
  testing nothing.
