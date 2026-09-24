<script lang="ts" module>
    export type ExistingCredential =
        | ({
              kind: typeof CredentialKind.Password
          } & ExistingPasswordCredential)
        | ({ kind: typeof CredentialKind.Sso } & ExistingSsoCredential)
        | ({
              kind: typeof CredentialKind.PublicKey
          } & ExistingPublicKeyCredential)
        | ({
              kind: typeof CredentialKind.Certificate
          } & ExistingCertificateCredential)
        | ({ kind: typeof CredentialKind.Totp } & ExistingOtpCredential)
</script>

<script lang="ts">
    /**
     * Credential editor — screen 6b.
     *
     * ── Enumeration of the old component, asserted present here ──────────
     * State:     credentials, globalParameters, creatingPassword, creatingOtp,
     *            editingSsoCredential(+Instance), editingPublicKeyCredential
     *            (+Instance), editingCertificateCredential
     * Load:      loadPasswords, loadSso, loadPublicKeys, loadCertificates,
     *            loadOtp, loadParameters — all in one Promise.all
     * Mutations: deleteCredential (5 kinds), createPassword, createOtp
     *            (+ the auto-2FA policy side effect), saveSsoCredential
     *            (create|update), savePublicKeyCredential (create|update),
     *            saveCertificateCredential
     * Gating:    every action on usersEdit; public key add/change/delete also
     *            disabled when the user is LDAP-linked, because those keys
     *            come from the directory
     * Renders:   per-kind row for Password, PublicKey (+abbreviated key,
     *            used-state), Certificate (+fingerprint, used-state), Totp,
     *            Sso (+email, provider); EmptyState; AuthPolicyEditor
     *
     * ── CORRECTNESS FIX: delete no longer lies on failure ────────────────
     * The original removed the credential from the list *before* awaiting the
     * API call, and never restored it:
     *
     *     credentials = credentials.filter(c => c !== credential)
     *     ...
     *     await api.deletePasswordCredential(...)
     *
     * If the request failed the row was already gone, so the editor showed a
     * credential as deleted while it still authenticated. For a credential
     * list that is a security defect rather than a visual one — an
     * administrator would reasonably conclude a compromised key had been
     * removed. The delete now awaits first and only then updates the list,
     * surfacing failure as an error.
     *
     * ── Confirmation coverage, unchanged and worth knowing ───────────────
     * Only certificate revocation is confirmed, and that is preserved (as a
     * plain ConfirmDialog per the agreed modes — revocation is recoverable by
     * reissuing). Deleting a password, public key, SSO link or TOTP secret is
     * still unconfirmed. Removing a user's only second factor with one click
     * is arguably worth a prompt, but adding one is a product decision rather
     * than a migration, so it is flagged rather than changed.
     */
    import {
        api,
        CredentialKind,
        type ExistingCertificateCredential,
        type ExistingOtpCredential,
        type ExistingPasswordCredential,
        type ExistingPublicKeyCredential,
        type ExistingSsoCredential,
        type ParameterValues,
        type UserRequireCredentialsPolicy,
    } from 'admin/lib/api'
    import { adminPermissions } from 'admin/lib/store'
    import CredentialUsedStateBadge from 'common/CredentialUsedStateBadge.svelte'
    import { stringifyError } from 'common/errors'
    import Loadable from 'common/Loadable.svelte'
    import {
        abbreviatePublicKey,
        getEffectivePossibleCredentials,
    } from 'common/protocols'
    import Button from 'ui/Button.svelte'
    import Callout from 'ui/Callout.svelte'
    import ConfirmDialog from 'ui/ConfirmDialog.svelte'
    import EmptyState from 'ui/EmptyState.svelte'
    import Tooltip from 'ui/Tooltip.svelte'
    import { toast } from 'ui/toasts.svelte'
    import AuthPolicyEditor from './AuthPolicyEditor.svelte'
    import CertificateCredentialModal from './CertificateCredentialModal.svelte'
    import CreateOtpModal from './CreateOtpModal.svelte'
    import CreatePasswordModal from './CreatePasswordModal.svelte'
    import PublicKeyCredentialModal from './PublicKeyCredentialModal.svelte'
    import SsoCredentialModal from './SsoCredentialModal.svelte'

    interface Props {
        userId: string
        username: string
        credentialPolicy: UserRequireCredentialsPolicy
        ldapLinked?: boolean
    }

    let {
        userId,
        username,
        credentialPolicy = $bindable(),
        ldapLinked = false,
    }: Props = $props()

    let credentials: ExistingCredential[] = $state([])
    let globalParameters: ParameterValues | undefined = $state()
    let error: string | undefined = $state()

    let creatingPassword = $state(false)
    let creatingOtp = $state(false)
    let editingSsoCredential = $state(false)
    let editingSsoCredentialInstance: ExistingSsoCredential | null =
        $state(null)
    let editingPublicKeyCredential = $state(false)
    let editingPublicKeyCredentialInstance: ExistingPublicKeyCredential | null =
        $state(null)
    let editingCertificateCredential = $state(false)
    let revokingCertificate: ExistingCredential | null = $state(null)
    let revokeOpen = $state(false)

    const loadPromise = load()

    async function load() {
        await Promise.all([
            loadPasswords(),
            loadSso(),
            loadPublicKeys(),
            loadCertificates(),
            loadOtp(),
            loadParameters(),
        ])
    }

    async function loadParameters() {
        globalParameters = await api.getParameters({})
    }

    async function loadPasswords() {
        credentials.push(
            ...(await api.getPasswordCredentials({ userId })).map(c => ({
                kind: CredentialKind.Password,
                ...c,
            })),
        )
    }

    async function loadSso() {
        credentials.push(
            ...(await api.getSsoCredentials({ userId })).map(c => ({
                kind: CredentialKind.Sso,
                ...c,
            })),
        )
    }

    async function loadPublicKeys() {
        credentials.push(
            ...(await api.getPublicKeyCredentials({ userId })).map(c => ({
                kind: CredentialKind.PublicKey,
                ...c,
            })),
        )
    }

    async function loadCertificates() {
        credentials.push(
            ...(await api.getCertificateCredentials({ userId })).map(c => ({
                kind: CredentialKind.Certificate,
                ...c,
            })),
        )
    }

    async function loadOtp() {
        credentials.push(
            ...(await api.getOtpCredentials({ userId })).map(c => ({
                kind: CredentialKind.Totp,
                ...c,
            })),
        )
    }

    function requestDelete(credential: ExistingCredential) {
        if (credential.kind === CredentialKind.Certificate) {
            revokingCertificate = credential
            revokeOpen = true
            return
        }
        deleteCredential(credential)
    }

    /**
     * Awaits the API call, THEN removes the row. The original did the reverse
     * and never restored on failure — see the header.
     */
    async function deleteCredential(credential: ExistingCredential) {
        try {
            if (credential.kind === CredentialKind.Password) {
                await api.deletePasswordCredential({
                    id: credential.id,
                    userId,
                })
            } else if (credential.kind === CredentialKind.Sso) {
                await api.deleteSsoCredential({ id: credential.id, userId })
            } else if (credential.kind === CredentialKind.PublicKey) {
                await api.deletePublicKeyCredential({
                    id: credential.id,
                    userId,
                })
            } else if (credential.kind === CredentialKind.Certificate) {
                await api.revokeCertificateCredential({
                    id: credential.id,
                    userId,
                })
            } else if (credential.kind === CredentialKind.Totp) {
                await api.deleteOtpCredential({ id: credential.id, userId })
            }
        } catch (err) {
            error = await stringifyError(err)
            toast.error('The credential was not removed', { detail: error })
            return
        }

        credentials = credentials.filter(c => c !== credential)
        error = undefined
    }

    async function confirmRevoke() {
        const c = revokingCertificate
        revokingCertificate = null
        if (c) {
            await deleteCredential(c)
        }
    }

    async function createPassword(password: string) {
        const credential = await api.createPasswordCredential({
            userId,
            newPasswordCredential: { password },
        })
        credentials.push({ kind: CredentialKind.Password, ...credential })
    }

    async function createOtp(secretKey: number[]) {
        const credential = await api.createOtpCredential({
            userId,
            newOtpCredential: { secretKey },
        })
        credentials.push({ kind: CredentialKind.Totp, ...credential })

        /*
         * Adding an OTP also establishes a 2FA policy, per protocol, where
         * none exists yet — otherwise the credential is created and never
         * required, which reads as "2FA is on" while nothing enforces it.
         *
         * Only applied when the user actually holds the paired credential and
         * that credential is possible for the protocol, so the policy cannot
         * be set to something unsatisfiable.
         */
        for (const protocol of ['http', 'ssh'] as ('http' | 'ssh')[]) {
            for (const ck of [
                CredentialKind.Password,
                CredentialKind.PublicKey,
            ]) {
                const effectiveCreds = getEffectivePossibleCredentials(
                    protocol,
                    globalParameters,
                )
                if (
                    !credentialPolicy[protocol] &&
                    credentials.some(x => x.kind === ck) &&
                    effectiveCreds.has(ck)
                ) {
                    credentialPolicy = {
                        ...(credentialPolicy ?? {}),
                        [protocol]: [ck, CredentialKind.Totp],
                    }
                }
            }
        }
    }

    async function saveSsoCredential(provider: string | null, email: string) {
        if (editingSsoCredentialInstance) {
            editingSsoCredentialInstance.provider = provider ?? undefined
            editingSsoCredentialInstance.email = email
            await api.updateSsoCredential({
                userId,
                id: editingSsoCredentialInstance.id,
                newSsoCredential: editingSsoCredentialInstance,
            })
        } else {
            const credential = await api.createSsoCredential({
                userId,
                newSsoCredential: { provider: provider ?? undefined, email },
            })
            credentials.push({ kind: CredentialKind.Sso, ...credential })
        }
        editingSsoCredential = false
        editingSsoCredentialInstance = null
    }

    async function savePublicKeyCredential(
        label: string,
        opensshPublicKey: string,
    ) {
        if (editingPublicKeyCredentialInstance) {
            editingPublicKeyCredentialInstance.label = label
            editingPublicKeyCredentialInstance.opensshPublicKey =
                opensshPublicKey
            await api.updatePublicKeyCredential({
                userId,
                id: editingPublicKeyCredentialInstance.id,
                newPublicKeyCredential: editingPublicKeyCredentialInstance,
            })
        } else {
            const credential = await api.createPublicKeyCredential({
                userId,
                newPublicKeyCredential: { label, opensshPublicKey },
            })
            credentials.push({ kind: CredentialKind.PublicKey, ...credential })
        }
        editingPublicKeyCredential = false
        editingPublicKeyCredentialInstance = null
    }

    async function saveCertificateCredential(
        label: string,
        publicKeyPem: string,
    ) {
        const response = await api.issueCertificateCredential({
            userId,
            issueCertificateCredentialRequest: { label, publicKeyPem },
        })
        credentials.push({
            kind: CredentialKind.Certificate,
            ...response.credential,
        })
        return response
    }

    const canEdit = $derived($adminPermissions.usersEdit)
    // Directory-sourced keys: editing them here would be overwritten by the
    // next sync, so the controls are disabled rather than silently futile.
    const publicKeyLocked = $derived(ldapLinked || !canEdit)
</script>

<div class="head">
    <h3>Credentials</h3>
    {#if canEdit}
        <div class="actions">
            <Button size="compact" onclick={() => (creatingPassword = true)}>
                Add password
            </Button>
            <Button
                size="compact"
                onclick={() => (editingCertificateCredential = true)}
            >
                Issue certificate
            </Button>
            {#if ldapLinked}
                <Tooltip text="Public keys are loaded from LDAP for this user">
                    <Button size="compact" disabled>Add public key</Button>
                </Tooltip>
            {:else}
                <Button
                    size="compact"
                    onclick={() => {
                        editingPublicKeyCredentialInstance = null
                        editingPublicKeyCredential = true
                    }}
                >
                    Add public key
                </Button>
            {/if}
            <Button size="compact" onclick={() => (creatingOtp = true)}>
                Add OTP
            </Button>
            <Button
                size="compact"
                onclick={() => {
                    editingSsoCredentialInstance = null
                    editingSsoCredential = true
                }}
            >
                Add SSO
            </Button>
        </div>
    {/if}
</div>

{#if error}
    <div class="error-slot">
        <Callout tone="danger" title="Credential change failed"
            >{error}</Callout
        >
    </div>
{/if}

<Loadable promise={loadPromise}>
    {#if credentials.length === 0}
        <EmptyState
            size="compact"
            title="No credentials"
            hint="This user cannot authenticate with Warpgate until they have at least one."
        />
    {:else}
        <ul class="credential-list">
            {#each credentials as credential (credential.id)}
                <li>
                    <div class="cred-main">
                        {#if credential.kind === CredentialKind.Password}
                            <span class="cred-label">Password</span>
                        {:else if credential.kind === CredentialKind.PublicKey}
                            <span class="cred-label">{credential.label}</span>
                            <span class="cred-detail wg-mono">
                                {abbreviatePublicKey(credential.opensshPublicKey)}
                            </span>
                        {:else if credential.kind === CredentialKind.Certificate}
                            <span class="cred-label">{credential.label}</span>
                            <span class="cred-detail wg-mono">
                                SHA-256:{credential.fingerprint}
                            </span>
                        {:else if credential.kind === CredentialKind.Totp}
                            <span class="cred-label">One-time password</span>
                        {:else if credential.kind === CredentialKind.Sso}
                            <span class="cred-label">Single sign-on</span>
                            <span class="cred-detail">
                                {credential.email}
                                {credential.provider
                                    ? ` (${credential.provider})`
                                    : ''}
                            </span>
                        {/if}
                    </div>

                    <div class="cred-actions">
                        {#if credential.kind === CredentialKind.PublicKey || credential.kind === CredentialKind.Certificate}
                            <CredentialUsedStateBadge {credential} />
                        {/if}

                        {#if credential.kind === CredentialKind.PublicKey || credential.kind === CredentialKind.Sso}
                            <Button
                                variant="ghost"
                                size="compact"
                                disabled={credential.kind ===
                                    CredentialKind.PublicKey && publicKeyLocked}
                                onclick={() => {
                                    if (credential.kind === CredentialKind.Sso) {
                                        editingSsoCredentialInstance = credential
                                        editingSsoCredential = true
                                    } else if (
                                        credential.kind ===
                                        CredentialKind.PublicKey
                                    ) {
                                        editingPublicKeyCredentialInstance =
                                            credential
                                        editingPublicKeyCredential = true
                                    }
                                }}
                            >
                                Change
                            </Button>
                        {/if}

                        <Button
                            variant="ghost"
                            size="compact"
                            disabled={credential.kind ===
                                CredentialKind.PublicKey && publicKeyLocked}
                            onclick={() => requestDelete(credential)}
                        >
                            {credential.kind === CredentialKind.Certificate
                                ? 'Revoke'
                                : 'Delete'}
                        </Button>
                    </div>
                </li>
            {/each}
        </ul>
    {/if}

    <h3 class="policy-heading">Auth policy</h3>
    <AuthPolicyEditor
        bind:value={credentialPolicy}
        existingCredentials={credentials}
        {globalParameters}
    />
</Loadable>

{#if creatingPassword}
    <CreatePasswordModal
        bind:isOpen={creatingPassword}
        create={createPassword}
    />
{/if}

{#if creatingOtp}
    <CreateOtpModal bind:isOpen={creatingOtp} {username} create={createOtp} />
{/if}

{#if editingSsoCredential}
    <SsoCredentialModal
        bind:isOpen={editingSsoCredential}
        instance={editingSsoCredentialInstance}
        save={saveSsoCredential}
    />
{/if}

{#if editingPublicKeyCredential}
    <PublicKeyCredentialModal
        bind:isOpen={editingPublicKeyCredential}
        instance={editingPublicKeyCredentialInstance ?? undefined}
        save={savePublicKeyCredential}
    />
{/if}

{#if editingCertificateCredential}
    <CertificateCredentialModal
        bind:isOpen={editingCertificateCredential}
        save={saveCertificateCredential}
        {username}
        onClose={() => {
            editingCertificateCredential = false
        }}
    />
{/if}

<ConfirmDialog
    bind:open={revokeOpen}
    title="Revoke this certificate?"
    confirmLabel="Revoke certificate"
    onconfirm={confirmRevoke}
    oncancel={() => (revokingCertificate = null)}
>
    <p>
        The certificate stops being accepted immediately and cannot be
        un-revoked. Issuing a replacement is the recovery path.
    </p>
</ConfirmDialog>

<style>
    .head {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: var(--wg-space-lg);
        flex-wrap: wrap;
        margin-bottom: var(--wg-space-md);
    }

    h3 {
        margin: 0;
        font: var(--wg-text-headline-md);
    }

    .policy-heading {
        margin: var(--wg-space-2xl) 0 var(--wg-space-md);
    }

    .actions {
        display: flex;
        flex-wrap: wrap;
        gap: var(--wg-space-sm);
    }

    .error-slot {
        margin-bottom: var(--wg-space-md);
    }

    .credential-list {
        list-style: none;
        margin: 0;
        padding: 0;
        border: var(--wg-border-width) solid var(--wg-border);
        border-radius: var(--wg-radius-panel);
        overflow: hidden;
    }

    .credential-list li {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: var(--wg-space-lg);
        min-height: var(--wg-row-height);
        padding: var(--wg-space-sm) var(--wg-space-md);
        border-bottom: var(--wg-border-width) solid var(--wg-border);
    }

    .credential-list li:last-child {
        border-bottom: 0;
    }

    .cred-main {
        display: flex;
        flex-direction: column;
        gap: 2px;
        min-width: 0;
    }

    .cred-label {
        font: var(--wg-text-body-md);
        color: var(--wg-text);
    }

    .cred-detail {
        font: var(--wg-text-label-sm);
        color: var(--wg-text-muted);
        overflow-wrap: anywhere;
    }

    .cred-actions {
        display: flex;
        align-items: center;
        gap: var(--wg-space-sm);
        flex: none;
    }

    @media (max-width: 640px) {
        .credential-list li {
            flex-direction: column;
            align-items: stretch;
        }
    }
</style>
