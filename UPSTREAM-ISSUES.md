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

## 4. Audit log search races itself: results can belong to a stale query

**Where:** `warpgate-web/src/admin/log-viewer/LogViewer.svelte`

The search box calls `search()` on every `keyup`, and `search()` calls
`loadOlder(true)`, which issues a `getLogs` POST and assigns the result
unconditionally:

```ts
function search() {
    loadOlder(true)
}

async function loadOlder(searchMode = false) {
    ...
    const newItems = await getLogs({ ... })   // no request identity
    if (searchMode) {
        endReached = false
        items = []
    }
    addItems(newItems)                        // last response wins
    visibleItems = items
}
```

There is no debounce and no request-ordering guard. Typing `ssh` issues three
requests — for `s`, `ss` and `ssh` — and whichever **resolves** last is the one
rendered. Responses are not required to arrive in the order they were sent, and
a broader prefix is usually the slower query because it matches more rows, so
the racing case is the common one rather than the pathological one.

**Why it matters more than a normal debounce omission.** The failure is silent
and it is in an audit tool: the search box reads `ssh`, the list shows the
result set for `ss`, and nothing indicates a mismatch. An operator scanning the
audit log for a specific event can conclude it is absent when it is not. For a
log that exists to answer "did this happen", a filter that quietly shows the
wrong result set is a correctness bug, not a performance one.

It also issues one POST per keystroke against the audit log table, which is the
largest table in the database.

**The fix already exists in this repository.** `admin/player/latestWins.ts`
implements exactly this guard and is used by `playbackController`. Applying it
to `loadOlder`, plus a short debounce on `search()`, would fix both halves.

**Not changed here.** The redesign's scope for this component is chrome only —
the virtualizer, streaming and pagination are deliberately untouched — and this
is internals. The search input was migrated to `ui/Input` preserving `onkeyup`
exactly, rather than silently switching to `oninput` or adding a debounce,
so the behaviour is unchanged and this report describes the code as it stands.

## 5. The "you need a password" warning tests the wrong collection

**Where:** `warpgate-web/src/gateway/CredentialManager.svelte`

The portal's credential page shows four "your credential policy requires X"
warnings. Three test their own collection against their own kind. The password
one tests the **public key** collection:

```svelte
{#if creds.publicKeys.length === 0 && Object.values(creds.credentialPolicy).some(l => l?.includes(CredentialKind.Password))}
    Your credential policy requires using a password for authentication.
    Without one, you won't be able to log in.
{/if}
```

Its three siblings, for comparison:

```svelte
{#if creds.otp.length === 0          && ... CredentialKind.Totp}
{#if creds.publicKeys.length === 0   && ... CredentialKind.PublicKey}
{#if creds.certificates.length === 0 && ... CredentialKind.Certificate}
```

It is a copy-paste from the public-key block immediately below it.

**The effect is wrong in both directions.** A user who has a password but no
public keys is told they will not be able to log in, which is false and
alarming. A user who has public keys but **no password**, under a policy that
requires one, sees nothing — and that is precisely the case the warning exists
to catch. The warning is silent exactly when it matters.

**Fix:** test the password state, which is what the message is about.

```svelte
{#if creds.password === PasswordState.Unset && Object.values(creds.credentialPolicy).some(l => l?.includes(CredentialKind.Password))}
```

**Changed in this fork,** unlike issues 1–4. The message is purely
informational, the intent is unambiguous from the three sibling blocks, and
this markup was being rewritten anyway. Called out in the screen 14 commit.

## 6. Creating or deleting an API token does not update the list

**Where:** `warpgate-web/src/gateway/ApiTokenManager.svelte`

The component keeps `tokens` state and also renders a `Loadable` whose snippet
parameter is **also** called `tokens`:

```svelte
let tokens: ExistingApiToken[] = $state([])
...
<Loadable promise={api.getMyApiTokens()}>
    {#snippet children(tokens)}      <!-- shadows the state above -->
        {#each tokens as token (token.id)}
```

`createToken` and `deleteToken` both write to the outer `tokens`, which nothing
renders. The outer one is initialised to `[]` and never loaded. So a token that
was just created does not appear in the list, and a deleted one does not go
away, until the page is reloaded — and the newly created secret is displayed
above a list that does not contain it, which reads as a failed creation.

`deleteToken` also removes the row before awaiting the call and never restores
it on failure, so a rejected delete is indistinguishable from a successful one.

**Fix:** load into the state variable and render from it; await the delete
before removing the row.

**Changed in this fork** as part of the screen 14 migration, since the shadowed
render was in the markup being replaced.

## 7. "Auto-link SSO users" cannot be set when an LDAP server is created

`warpgate-web/src/admin/config/ldap/CreateLdapServer.svelte`

```svelte
let autoLinkSsoUsers = $state(false)
...
await api.createLdapServer({
    ...
    autoLinkSsoUsers,
})
```

The value is declared, sent to the API, and **never assigned by anything**. The
create form has no control for it, so every LDAP server is created with
`autoLinkSsoUsers: false` regardless of what the operator wants.

The edit screen (`LdapServer.svelte`) does have the checkbox, so the setting is
reachable — but only by creating the server first and then editing it. Anyone
who fills in the create form expecting it to be complete gets a directory that
silently does not auto-link, which for an SSO-backed deployment means users
arriving through SSO are not matched to their directory accounts until someone
notices.

Present since `4f16a7b1` (LDAP user sync, #1603), which introduced the variable
and the payload field together without the control.

**Fix:** add the checkbox to the create form, next to the other directory
options, defaulting to whatever the edit screen defaults to.

**Not changed in this fork.** Adding the control changes what the screen sends
to the API, which is behaviour rather than presentation, and this redesign is
scoped to presentation. Reported rather than fixed.
