---
author: Dat Ho
pubDatetime: 2026-09-22T00:00:00Z
title: 'Envelope encryption for multi-tenant secrets: the parts nobody draws on the whiteboard'
description: "Per-tenant data keys wrapped by a KMS master key, lazy rewrap on read, forced rotation, and the storage decision I got wrong the first time. A walkthrough of an actual implementation, including what the adversarial tests found and the one feature I decided not to build."
tags: [security, cryptography, dotnet, event-sourcing, aws]
featured: true
draft: false
---

I needed somewhere to put tenant secrets. API keys, database passwords, tokens: the boring,
high-value stuff a multi-tenant system accumulates, all of it in one shared Postgres database.
Encrypting it is the obvious part. The part that actually shapes the design is what happens
eighteen months later when the key has to change, and the answer cannot be "decrypt and
re-encrypt every row in the system".

That constraint is what envelope encryption exists for, and most explanations of it stop at the
two-sentence version: you encrypt data with a data key, and encrypt the data key with a master
key. True, and not enough to build from. The interesting decisions are all downstream of it. How
do you detect that the master key moved? What does a read cost when it did? Where does the
ciphertext physically live, and can you ever delete it? I got one of those wrong on the first
pass and had to undo it, so this is a writeup of the whole thing, including the undo.

## Table of contents

## Two keys, because one key has no exit

The problem with encrypting everything under a single key is not that it is insecure. It is that
it has no exit. Rotating that key means touching every encrypted byte you own, in one operation,
with no partial-failure story. So you split the job:

- A **master key** that lives in a KMS (AWS KMS here) and never leaves it. The application cannot
  read it, only ask KMS to perform operations with it.
- A **data encryption key** (DEK) per tenant, AES-256, which actually encrypts secret values.
  It lives in plaintext only in process memory, and is persisted only in wrapped form, encrypted
  by the master key.

This is not a clever local invention, it is the shape both major clouds converged on. Azure's
[data encryption at rest](https://learn.microsoft.com/en-us/azure/security/fundamentals/encryption-atrest)
documentation calls the outer key a key encryption key and spells out the same reasoning:

> Azure encryption at rest models use envelope encryption, where a KEK encrypts a data encryption
> key (DEK). [...] Limiting the use of a single encryption key decreases the risk that the key is
> compromised and the cost of re-encryption when a key must be replaced.
>
> <cite>Microsoft, [Azure data encryption at rest](https://learn.microsoft.com/en-us/azure/security/fundamentals/encryption-atrest)</cite>

That last clause is the whole design in one sentence. Risk and re-encryption cost both scale with
how much data sits under a single key, so you put very little under the outer one.

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

Rotating the master key now costs one small KMS call per tenant instead of a full re-encryption
of the corpus, because all that changes is the wrapping around a DEK that is maybe 32 bytes long.
The plaintext secrets underneath never move.

Per tenant rather than global is a blast radius decision. If one tenant's DEK is somehow exposed,
the damage stops at that tenant. It also makes "rotate everything for this one customer because
they think they were breached" a real operation you can offer, instead of an apology.

The abstraction over KMS is deliberately small, four methods, because nothing above it should
know or care that it is AWS:

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

`RewrapAsync` is the one worth pointing at. It maps to KMS
[`ReEncrypt`](https://docs.aws.amazon.com/kms/latest/APIReference/API_ReEncrypt.html), which the
API reference describes as:

> Decrypts ciphertext and then reencrypts it entirely within AWS KMS. You can use this operation to
> change the KMS key under which data is encrypted, such as when you manually rotate a KMS key or
> change the KMS key that protects a ciphertext.
>
> <cite>AWS, [KMS API Reference: ReEncrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_ReEncrypt.html)</cite>

"Entirely within AWS KMS" is the part that matters. The wrapped DEK moves onto current key material
without the plaintext DEK ever coming back to the caller, which is why "the master key rotated" does
not have to mean "the application briefly holds every tenant's key in memory".

## The cipher, and why GCM rather than CBC

The cipher layer is small enough to read in one sitting. It takes a plaintext DEK and a string,
and does authenticated encryption:

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

GCM instead of CBC for one reason: the authentication tag. With CBC, tampering with stored
ciphertext gets you garbage plaintext, and garbage plaintext is something an application will
happily hand to a caller as if it were real. With GCM, `Decrypt` throws when the tag does not
verify, so a corrupted row fails the request instead of quietly returning a wrong API key that
then gets used against a live third-party service. Failing closed is worth more here than any
performance difference between the modes.

The fresh random nonce per encryption matters more than it looks. It means encrypting the same
value twice produces different ciphertext both times, so nobody who steals the table can tell
which tenants share a password or whether today's value matches last year's. Hold onto that
property, because later on there is a feature that would have thrown it away.

## Where the ciphertext lives, and the version I had to undo

The vault is event-sourced (Marten, one stream per tenant). Events give an audit trail for free,
which is exactly what you want for a secrets store: every write, every read, every rotation,
timestamped and append-only.

So the first version put everything in the stream. `SecretStored` carried the nonce, ciphertext
and tag. Clean, single source of truth, and wrong.

Append-only means append-only. Nothing you write to that stream can ever be taken back out. The
moment someone asks "can you delete this secret", and someone always does, whether for offboarding
or a compliance request, the honest answer with ciphertext in the log is no. Marten's
`ArchiveStream` flags a stream rather than removing the rows. Write-ahead logs and backups keep
their copies regardless. A hard `DELETE` against the events table works against the grain of the
entire framework and, more to the point, against the grain of event sourcing itself: the log is
supposed to be the thing you can trust never changed.

The fix was to stop asking the event stream to do a job it was never designed for:

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
went into `EncryptedSecretDocument`, an ordinary mutable Marten document, one row per tenant and
secret name, deletable with a normal `session.Delete<T>(id)`. The vault aggregate kept only DEK
bookkeeping, which was never secret material to begin with:

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

There is a tempting counterargument here, which is that envelope encryption already gives you a
delete primitive. Azure makes the point directly:

> Because decrypting the DEKs requires the KEK, you can cryptographically erase DEKs and data by
> disabling the KEK.
>
> <cite>Microsoft, [Azure data encryption at rest](https://learn.microsoft.com/en-us/azure/security/fundamentals/encryption-atrest)</cite>

True, and it does not rescue the original design, because cryptographic erasure works at the
granularity of a key. Destroying key material erases everything that key protects. "Delete this one
secret and keep the other forty for this tenant" is a row-level operation, and no amount of key
management performs it. If you want per-secret deletion you need per-secret storage you can delete,
which is the conclusion I arrived at the slow way.

The useful way to state the rule I extracted from this: an append-only log is the right place for
things that are true forever, and a secret value is not one of those. "Tenant X wrote a secret
named `stripe-key` at 14:02" is true forever. The value of that key is true until someone rotates
it, and might need to be erasable on demand. Those are different lifetimes, so they belong in
different storage.

## Two kinds of rotation, because they cost wildly different amounts

Once the master key can move, you need an answer for what to do about DEKs wrapped by the old
material. There are two separate operations here and conflating them is expensive.

**Lazy rewrap on read** is the cheap one. The master key rotated, so the DEK's *wrapping* is
stale. The DEK itself is fine, and every secret encrypted under it is fine. So on the next read
for that tenant, ask KMS to `ReEncrypt` the wrapped DEK, append a `DekRewrapped` event, and move
on. Cost: one small KMS call and one small event. No secret value is touched.

**Forced rotation** is the expensive one. A brand new DEK gets minted and every secret the tenant
owns is decrypted under the old DEK and re-encrypted under the new one, in a single transaction:

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
    session.Store(doc);

    events += new SecretReencrypted { Name = doc.Name, ReencryptedAt = now };
}
```

That is an O(n) write behind an admin endpoint, appropriate for a suspected compromise or a
compliance-driven crypto-period limit, and completely inappropriate as an automatic response to
a routine KMS master key rotation. If you wire those together, every scheduled key rotation turns
into a full re-encryption of every tenant's data, which is precisely the thing envelope encryption
was supposed to save you from.

## The staleness check, and the thing AWS makes annoying

To rewrap lazily you first have to know the wrapping is stale, and this turned out to be the
fiddliest part of the whole design.

If you manage rotation by repointing an alias at a new CMK, detection is easy: resolve the alias,
compare the resulting ARN against the `KeyVersionId` stored on the aggregate, and if they differ
it is stale. That is what `GetCurrentKeyVersionAsync` does, via `DescribeKey`.

AWS KMS *automatic* rotation does not work like that. It rotates the backing key material
transparently under the same key ARN, which the
[rotation documentation](https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html)
is explicit about:

> The KMS key is the same logical resource, regardless of whether or how many times its key material
> changes. The properties of the KMS key do not change.
>
> <cite>AWS, [Rotate AWS KMS keys](https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html)</cite>

So the ARN I compare against is identical before and after, and the comparison above silently
stops detecting anything. The implementation falls back to time:

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

Which is the first problem with the 180 day constant: it is tuned to a default that whoever owns the
key can change without telling me, and nothing in the code notices.

The second problem is worse, and I only found it while writing this post. My justification for the
time fallback was that key material has no API-exposed identifier, so there is nothing to compare.
That is no longer true. KMS returns a `KeyMaterialId` on the operations I am already calling.
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

So the correct design is to store the `KeyMaterialId` returned by `GenerateDataKey` rather than
(or alongside) the key ARN, and compare that. It is an exact signal for precisely the case the
180 day heuristic was invented to paper over, it costs no extra API call because the value comes
back on a call already being made, and it would let the whole `AutomaticRotationFallbackWindow`
option be deleted. That is the change I would make first if I picked this back up.

It is worth being clear about what rewrapping does and does not buy you either way. AWS is blunt
about it:

> Key rotation has no effect on the data that the KMS key protects. It does not rotate the data keys
> that the KMS key generated or re-encrypt any data protected by the KMS key. Key rotation will not
> mitigate the effect of a compromised data key.
>
> <cite>AWS, [Rotate AWS KMS keys](https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html)</cite>

Which is exactly why both rotation paths have to exist. Master key rotation is a compliance and
hygiene operation, and it is cheap. A compromised DEK is a different incident entirely, and the
only answer to it is the expensive O(n) re-encryption behind the admin endpoint.

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

KMS calls are billed and they are network round trips, so a naive implementation of the above is
quietly terrible: every read would unwrap the DEK *and* call `DescribeKey` to check staleness.
Two KMS calls per secret read, both of them almost always returning the same answer as last time.

Two caches fix it, and they cache different things for different reasons.

The first is a plaintext DEK cache, keyed by tenant and key version, with a TTL (five minutes by
default). Repeated reads for the same tenant within the window skip KMS entirely. The interesting
part is not the cache, it is the eviction. Keying on key version alone is not enough, because after
a rewrap the old entry is simply orphaned rather than wrong, and a plaintext DEK sitting in memory
past a rotation is exactly the thing you do not want. So each tenant's entries hang off a
cancellation token, and `Evict` cancels it to force immediate expiry:

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

I am instead keeping it for up to five minutes. That is a real tradeoff and worth naming as one:
a plaintext DEK resident in process memory is exposed to a memory disclosure bug or a heap dump for
as long as it sits there, and the payment for that risk is not calling KMS on every read. Azure's
documentation is more forgiving about the same pattern, describing locally cached DEKs as normal:

> When services cache DEKs locally for active cryptographic operations, Azure platform security
> controls protect the cached keys [...] Cached operational keys are an availability and performance
> mechanism, the KEK in Key Vault remains the root of trust, and key revocation governs access to
> encrypted data.
>
> <cite>Microsoft, [Azure data encryption at rest](https://learn.microsoft.com/en-us/azure/security/fundamentals/encryption-atrest)</cite>

Both are right, they are just pricing different risks. The honest summary is that the TTL is a dial
between KMS spend and memory exposure window, five minutes is a guess rather than a measured
choice, and anyone deploying this should set it deliberately.

The second cache is a decorator over `IMasterKeyService` that caches only `GetCurrentKeyVersionAsync`.
`Generate`, `Unwrap` and `Rewrap` pass straight through, deliberately. This exists purely because
the staleness check runs on every single read, and without it the "cheap" check would itself be a
billed KMS call every time, which would undo the entire point of doing lazy rewrap instead of
eager rotation. It is a small class that exists to stop a design from defeating itself.

## Testing it like someone who wants to break it

Round-trip unit tests on the cipher are table stakes. The more useful layer was a set of
adversarial integration tests running against a fully hosted instance (Alba, real Postgres, real
DI graph and middleware) that attempt the things an attacker would actually try. Three of them
matter.

The first checks the exact bytes of the GET response, because over-exposure is the kind of bug a
future refactor introduces by accident:

```csharp
var propertyNames = json.EnumerateObject().Select(p => p.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);
propertyNames.ShouldBe(["name", "value"], ignoreOrder: true);

raw.ShouldNotContain("WrappedDek");
raw.ShouldNotContain("Ciphertext");
raw.ShouldNotContain("Nonce");
raw.ShouldNotContain("KeyVersionId");
```

The second forces an error path with a tenant id containing SQL-injection-shaped characters and
asserts the response body carries no stack trace, no exception type names, no `Npgsql`.

The third is the one I would keep if I could only keep one. It goes around the application
entirely, opens its own Postgres connection, and corrupts the stored ciphertext in place:

```csharp
cmd.CommandText = """
    UPDATE mt_doc_encryptedsecretdocument
    SET data = jsonb_set(data, '{Ciphertext}', to_jsonb('AAAAAAAAAAAAAAAA'::text))
    WHERE id = @docId
    """;
```

Then it reads the secret back through the API and asserts the response is not a 200. That is the
GCM authentication tag doing its job, verified end to end against a real database rather than
assumed from the fact that we picked an AEAD mode. This test is also where I hit the most annoying
bug of the exercise: the tamper originally ran on a Marten session's connection, which does not
commit until `SaveChangesAsync`, so the subsequent GET ran on a different connection under
read-committed isolation and never saw the corruption. The test passed while testing nothing.
Hence the standalone auto-committing connection, and hence the `rowsAffected.ShouldBe(1)` assertion
on the setup itself, so a tamper that silently hits zero rows fails loudly instead of producing a
green test that means nothing.

These are written so that a red test is a real finding rather than a broken test, which makes them
re-verifiable by CI on every future change instead of a report that goes stale a week after it is
written.

Two honest gaps. Everything ran against an in-memory KMS double rather than real AWS KMS or a
local emulator, because the emulator needs the Docker socket and the sandbox did not have it, so
IAM policy correctness and real CMK rotation behaviour are untested. And authentication is
deliberately not part of this component at all: the tenant id is expected to come from a validated
JWT claim in the hosting application rather than being trusted from the route. That is a scoping
decision, and it is only defensible because it is written down; an unauthenticated secrets endpoint
that nobody documented as "someone else's job" is just a vulnerability with good intentions.

## The feature I decided not to build

The comparison product had searchable encryption, and "search encrypted fields without exposing
plaintext" reads like a pure win on a feature list. The standard implementation is a blind index:
store `HMAC-SHA256(indexKey, plaintextValue)` in a plain column next to the ciphertext, and query
on that.

It works because HMAC is deterministic. That is also the problem. The random-nonce property from
earlier, where the same value encrypted twice looks different both times, is what stops someone
who steals the table from linking rows together. A blind index puts that determinism back, in a
column, indexed, next to the data. Two tenants using the same password now have visibly identical
index values. An attacker with the table and the index key can also run an offline dictionary
attack against a low-entropy field at their leisure.

So it reopens exactly the exposure that random nonces and rotation were built to close, in exchange
for query convenience nobody had asked for. Secrets are looked up by name, and the name is not
sensitive. No requirement, no feature. A separate part of the system does have a genuine need for
searching an encrypted field, and there the blind index exists, scoped to that one field, with the
tradeoff written down next to it.

## What I would tell myself at the start

Five things, in the order they cost me time.

Re-read the provider's API reference before writing a workaround for its limitations. The 180 day
staleness window exists because I concluded key material had no observable identifier. It does, it
comes back on calls the code already makes, and I found that out by checking the docs while writing
this post rather than while building the thing. A heuristic that compensates for a missing API is
reasonable engineering; a heuristic that compensates for an API you did not finish reading is just
a bug with a configuration option attached.

Decide what "delete" means before choosing storage, not after. Event sourcing and secret material
have incompatible lifetimes, and I only found that out by building the wrong thing first. The
question "what happens when someone asks us to erase this" is a storage-architecture question, not
a feature request to handle later.

Separate rotating the wrapping from rotating the key. They sound like the same operation in a
design doc, and one costs a single small KMS call while the other rewrites every row a tenant owns.
Every meaningful decision in the rotation design falls out of keeping them apart.

Budget for the checks, not just the work. The staleness check was the thing that nearly made lazy
rewrap cost more than eager rotation, because a check that runs on every read is a hot path whether
or not you thought of it that way.

And write the adversarial tests so they fail when the system is vulnerable. The tamper test caught
a real transaction-isolation mistake in itself, which is a decent argument for asserting on your own
test setup. A security test that cannot fail is worse than no test, because it produces a green
check mark that somebody will believe.

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
