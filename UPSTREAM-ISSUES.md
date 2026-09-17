# Upstream issues

Bugs found in `warpgate-web` while working on this fork's UI redesign, written
up for reporting upstream. **None of these are changed in this fork** — each is
a behaviour change rather than a presentation one, and the redesign is
presentation-only.

Each entry is written to be pasted into an issue with minimal editing.

---

## 3. TOTP shared secrets are generated with `Math.random()`

**File:** `warpgate-web/src/admin/CreateOtpModal.svelte`
**Severity:** this one is worth treating as a security issue rather than a bug.

### What happens

The TOTP shared secret is generated as:

```ts
secretKey = Array.from({ length: 32 }, () => Math.floor(Math.random() * 255))
```

### Two defects

**1. `Math.random()` is not a CSPRNG.** It is a seeded pseudo-random generator
with no security guarantee, and in V8 it is `xorshift128+`. An attacker who can
observe enough outputs from the same browsing context can recover the internal
state and predict subsequent values — and the entire 32-byte secret is drawn
from one contiguous run. A TOTP secret that can be derived rather than guessed
makes the second factor decorative: the attacker generates valid codes without
ever seeing the user's device.

This is the same class as CWE-338 (use of a cryptographically weak PRNG in a
security context).

**2. `Math.floor(Math.random() * 255)` never yields 255.** `Math.random()`
returns `[0, 1)`, so the product is `[0, 255)` and the floor is `0..254`. Each
byte carries log2(255) ≈ 7.994 bits instead of 8, and one value in 256 is
absent from every position.

Measured over 6400 sampled bytes from the current expression: **maximum value
254, the value 255 never produced.** The same sample size from
`crypto.getRandomValues` produces 255 as expected.

The entropy loss is small on its own — about 2 bits across a 32-byte key — but
it confirms the line was not written with the byte range in mind, which is the
part that matters given defect 1.

### Suggested fix

```ts
const bytes = new Uint8Array(32)
crypto.getRandomValues(bytes)
secretKey = Array.from(bytes)
```

`crypto.getRandomValues` is available in every browser Warpgate's admin UI
supports, requires no import, and produces the same shape the rest of the flow
expects. Verified against the existing `otpauth`/`base32-encode` path: the
enrolment URI, the 6-digit token, `window: 1` validation and rejection of
stale codes all behave identically.

### Note

This fork has applied the fix in its redesigned credential editor. The issue is
reported because the original is what upstream ships.

---

## 1. Username field is editable for LDAP-linked users and read-only for local ones

**File:** `warpgate-web/src/admin/config/users/User.svelte`
**Affects:** admin UI, user detail, General section

### What happens

The username input is disabled based on the *absence* of an LDAP link:

```svelte
<Input bind:value={user.username} disabled={!user.ldapServerId} />
```

So:

| Account type | Username field |
|---|---|
| LDAP-linked | **editable** |
| Local | **read-only** |

### Why this looks inverted

For a local account the username is just an identifier, and editing it renames
the user.

For an LDAP-linked account **the username is the join key against the
directory.** Editing it does not rename anyone — it repoints the account at a
different directory entry, or at no entry at all, and the next sync reconciles
against whatever was typed. That is an authentication-mapping change wearing a
plain text field, with no confirmation and no indication that the field means
something different here than it does on a local account.

The local case is the harmless one and it is the one that is locked.

### Why it might be deliberate

Two possibilities that are not visible from the frontend, which is why this is
an issue rather than a patch:

- `autoLinkUserToLdap` / `unlinkUserFromLdap` may require the field to be
  writable during a re-link.
- There may be an intended "fix a mistyped DN mapping" workflow that depends on
  editing the username in place.

If either is the case, the field probably still wants a warning and a
confirmation rather than being a bare input.

### Suggested fix

If neither workflow depends on it, invert the condition:

```svelte
disabled={!!user.ldapServerId}
```

If one does, keep the field writable for linked users but surface what it
does — a callout stating that changing the username repoints the directory
mapping, and a typed confirmation on save.

---

## 2. Role assignment expiry is only validated client-side

**File:** `warpgate-web/src/admin/config/users/User.svelte` (`saveExpiry`),
API `PUT /users/{id}/roles/{role_id}`
**Affects:** access-role assignment expiry

### What happens

`saveExpiry` refuses to send an expiry in the past:

```ts
if (expiresAt && expiresAt.getTime() <= Date.now()) {
    error = 'Expiry date must be in the future.'
    return
}
```

**This client-side check is the only thing preventing it.** The API accepts a
past `expiresAt` and stores it. The assignment is then created already expired.

### Why it matters

The failure is silent and it fails in the unsafe direction for an operator's
mental model:

- an admin grants a role and it appears granted
- the assignment is expired from the moment it is written
- the user has no access, and the admin has no error to explain why

Anything that is not this exact form reaches the same endpoint without the
check — the API directly, a script, a future UI, or this UI if the guard is
ever refactored away. The guard currently has no test covering it.

### Reproduction

```
PUT /users/{id}/roles/{role_id}
{ "expiresAt": "2020-01-01T00:00:00Z" }
```

Returns success. `GET /users/{id}/roles` then reports the assignment with
`isExpired: true`.

### Suggested fix

Reject a past `expiresAt` server-side with a 400. Keep the client-side check as
a fast path — it gives a better message — but it should not be the only thing
enforcing the invariant.

Worth deciding explicitly whether "expiry equal to now" is valid; the current
client check uses `<=`, treating it as invalid.
