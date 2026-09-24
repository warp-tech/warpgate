<script lang="ts">
    /**
     * My credentials — screen 14. Migrated in place: both the old portal shell
     * and AppNew route to this same file, so one migration serves both.
     *
     * ── Enumeration of the original, asserted present ────────────────────
     * Data:   getMyCredentials; changeMyPassword writing the returned state
     *         back; addMyPublicKey / deleteMyPublicKey; addMyOtp /
     *         deleteMyOtp; issueMyCertificate returning the response to the
     *         modal; revokeMyCertificate followed by deleteCertificateKey so
     *         the browser-stored private key goes with the credential.
     * States: password Unset / Set / MultipleSet, each with its own label and
     *         its own button verb (Set password / Change / Reset password).
     * Policy: four "your policy requires X" warnings.
     * Guards: OTP delete disabled when otpSetupEnforced and it is the last
     *         device, with the reason in the title; Add key disabled and
     *         explained when the account is LDAP-linked.
     * Lists:  public keys with label and abbreviated form, certificates with
     *         label and SHA-256 fingerprint, read-only SSO identities, each
     *         carrying CredentialUsedStateBadge where it had one.
     *
     * ── FIXED: the password policy warning tested the wrong collection ───
     * The original condition was
     *
     *     creds.publicKeys.length === 0 && policy includes Password
     *
     * — a copy-paste from the public-key block below it. Its three siblings
     * each test their own collection against their own kind. The effect was
     * backwards in both directions: a user who had a password but no public
     * keys was told they could not log in, and a user who had public keys but
     * NO password saw nothing, which is precisely the case the warning exists
     * for. It now tests `creds.password === PasswordState.Unset`.
     *
     * This is a behaviour change and is called out in the commit; it is also
     * written up in UPSTREAM-ISSUES.md, since upstream still has it.
     *
     * ── Modals now point at the migrated versions ────────────────────────
     * All four came from admin/ and are replaced by their
     * admin/screens/user-detail/credentials/ equivalents, so the portal
     * inherits the fixes made in 6c — including the certificate modal no
     * longer leaving the previous credential's private key reachable behind a
     * "Copy as kubeconfig" button.
     */
    import CertificateCredentialModal from 'admin/screens/user-detail/credentials/CertificateCredentialModal.svelte'
    import CreateOtpModal from 'admin/screens/user-detail/credentials/CreateOtpModal.svelte'
    import CreatePasswordModal from 'admin/screens/user-detail/credentials/CreatePasswordModal.svelte'
    import PublicKeyCredentialModal from 'admin/screens/user-detail/credentials/PublicKeyCredentialModal.svelte'
    import CredentialUsedStateBadge from 'common/CredentialUsedStateBadge.svelte'
    import { stringifyError } from 'common/errors'
    import Loadable from 'common/Loadable.svelte'
    import {
        api,
        CredentialKind,
        type CredentialsState,
        type ExistingCertificateCredential,
        type ExistingOtpCredential,
        type ExistingPublicKeyCredential,
        PasswordState,
    } from 'gateway/lib/api'
    import { deleteCertificateKey } from 'gateway/lib/certificateStore'
    import { serverInfo } from 'gateway/lib/store'
    import Button from 'ui/Button.svelte'
    import Callout from 'ui/Callout.svelte'
    import ConfirmDialog from 'ui/ConfirmDialog.svelte'
    import Tooltip from 'ui/Tooltip.svelte'

    let creds: CredentialsState | undefined = $state()
    let error: string | undefined = $state()

    let creatingPublicKeyCredential = $state(false)
    let issuingCertificateCredential = $state(false)
    let creatingOtpCredential = $state(false)
    let changingPassword = $state(false)
    let revoking: ExistingCertificateCredential | undefined = $state()

    const initPromise = init()

    async function init() {
        creds = await api.getMyCredentials()
    }

    async function changePassword(password: string) {
        if (!creds) {
            return
        }
        const state = await api.changeMyPassword({
            changePasswordRequest: { password },
        })
        creds.password = state
    }

    async function createPublicKey(label: string, opensshPublicKey: string) {
        if (!creds) {
            return
        }
        const credential = await api.addMyPublicKey({
            newPublicKeyCredential: { label, opensshPublicKey },
        })
        creds.publicKeys.push(credential)
    }

    async function deletePublicKey(credential: ExistingPublicKeyCredential) {
        if (!creds) {
            return
        }
        // Await the call before removing the row. The original removed it
        // first and never put it back on failure, so a rejected delete looked
        // like a successful one until the page was reloaded.
        try {
            await api.deleteMyPublicKey(credential)
            creds.publicKeys = creds.publicKeys.filter(
                c => c.id !== credential.id,
            )
        } catch (err) {
            error = await stringifyError(err)
        }
    }

    async function createOtp(secretKey: number[]) {
        if (!creds) {
            return
        }
        const credential = await api.addMyOtp({
            newOtpCredential: { secretKey },
        })
        creds.otp.push(credential)
    }

    async function deleteOtp(credential: ExistingOtpCredential) {
        if (!creds) {
            return
        }
        try {
            await api.deleteMyOtp(credential)
            creds.otp = creds.otp.filter(c => c.id !== credential.id)
        } catch (err) {
            error = await stringifyError(err)
        }
    }

    async function issueCertificate(label: string, publicKeyPem: string) {
        const response = await api.issueMyCertificate({
            issueCertificateCredentialRequest: { label, publicKeyPem },
        })
        if (creds) {
            creds.certificates.push(response.credential)
        }
        return response
    }

    async function confirmRevoke() {
        const credential = revoking
        if (!creds || !credential) {
            return
        }
        try {
            await api.revokeMyCertificate(credential)
            // The locally stored private key is useless once the certificate
            // is revoked, and leaving it behind leaves key material in the
            // browser for a credential that no longer exists.
            await deleteCertificateKey(credential.id)
            creds.certificates = creds.certificates.filter(
                c => c.id !== credential.id,
            )
        } catch (err) {
            error = await stringifyError(err)
        } finally {
            revoking = undefined
        }
    }

    const otpDeleteBlocked = $derived(
        ($serverInfo?.otpSetupEnforced ?? false) &&
            (creds?.otp.length ?? 0) === 1,
    )
</script>

<Loadable promise={initPromise}>
    {#if creds}
        {@const c = creds}
        {#if error}
            <div class="notice">
                <Callout tone="danger" title="Something went wrong">
                    {error}
                </Callout>
            </div>
        {/if}

        <section>
            <div class="section-head">
                <h2>Password</h2>
            </div>

            <ul class="creds">
                <li>
                    <span class="cred-label">
                        {#if c.password === PasswordState.Unset}
                            Your account has no password set
                        {:else if c.password === PasswordState.Set}
                            Password set
                        {:else}
                            Multiple passwords set
                        {/if}
                    </span>
                    <Button
                        variant="ghost"
                        size="compact"
                        onclick={() => (changingPassword = true)}
                    >
                        {#if c.password === PasswordState.Unset}
                            Set password
                        {:else if c.password === PasswordState.Set}
                            Change
                        {:else}
                            Reset password
                        {/if}
                    </Button>
                </li>
            </ul>

            <!--
              FIXED: was `c.publicKeys.length === 0`, a copy-paste from the
              public-key block. See the file header.
            -->
            {#if c.password === PasswordState.Unset && Object.values(c.credentialPolicy).some(l => l?.includes(CredentialKind.Password))}
                <Callout tone="warning" title="You need a password">
                    Your credential policy requires a password for
                    authentication. Without one you will not be able to sign in.
                </Callout>
            {/if}
        </section>

        <section>
            <div class="section-head">
                <h2>One-time passwords</h2>
                <Button
                    variant="ghost"
                    size="compact"
                    onclick={() => (creatingOtpCredential = true)}
                >
                    Add device
                </Button>
            </div>

            <ul class="creds">
                {#each c.otp as credential (credential.id)}
                    <li>
                        <span class="cred-label">OTP device</span>
                        {#if otpDeleteBlocked}
                            <Tooltip
                                text="One-time passwords are required on this server — add another device first"
                            >
                                <Button variant="ghost" size="compact" disabled>
                                    Delete
                                </Button>
                            </Tooltip>
                        {:else}
                            <Button
                                variant="ghost"
                                size="compact"
                                click={() => deleteOtp(credential)}
                            >
                                Delete
                            </Button>
                        {/if}
                    </li>
                {/each}
            </ul>

            {#if c.otp.length === 0 && Object.values(c.credentialPolicy).some(l => l?.includes(CredentialKind.Totp))}
                <Callout tone="warning" title="You need a one-time password">
                    Your credential policy requires a one-time password for
                    authentication. Without one you will not be able to sign in.
                </Callout>
            {:else if $serverInfo?.otpSetupEnforced}
                <Callout
                    >One-time passwords are required on this server.</Callout
                >
            {/if}
        </section>

        <section>
            <div class="section-head">
                <h2>Public keys</h2>
                {#if c.ldapLinked}
                    <Tooltip
                        text="Public key credentials are loaded from LDAP for this account"
                    >
                        <Button variant="ghost" size="compact" disabled>
                            Add key
                        </Button>
                    </Tooltip>
                {:else}
                    <Button
                        variant="ghost"
                        size="compact"
                        onclick={() => (creatingPublicKeyCredential = true)}
                    >
                        Add key
                    </Button>
                {/if}
            </div>

            <ul class="creds">
                {#each c.publicKeys as credential (credential.id)}
                    <li>
                        <div class="cred-main">
                            <span class="cred-label">{credential.label}</span>
                            <small class="cred-sub wg-mono">
                                {credential.abbreviated}
                            </small>
                        </div>
                        <CredentialUsedStateBadge {credential} />
                        {#if c.ldapLinked}
                            <Tooltip text="SSH keys are managed by LDAP">
                                <Button variant="ghost" size="compact" disabled>
                                    Delete
                                </Button>
                            </Tooltip>
                        {:else}
                            <Button
                                variant="ghost"
                                size="compact"
                                click={() => deletePublicKey(credential)}
                            >
                                Delete
                            </Button>
                        {/if}
                    </li>
                {/each}
            </ul>

            {#if c.publicKeys.length === 0 && c.credentialPolicy.ssh?.includes(CredentialKind.PublicKey)}
                <Callout tone="warning" title="You need a public key">
                    Your credential policy requires a public key for SSH
                    authentication. Without one you will not be able to sign in.
                </Callout>
            {/if}
        </section>

        <section>
            <div class="section-head">
                <h2>Certificates</h2>
                <Button
                    variant="ghost"
                    size="compact"
                    onclick={() => (issuingCertificateCredential = true)}
                >
                    Issue certificate
                </Button>
            </div>

            <ul class="creds">
                {#each c.certificates as credential (credential.id)}
                    <li>
                        <div class="cred-main">
                            <span class="cred-label">{credential.label}</span>
                            <small class="cred-sub wg-mono">
                                SHA-256: {credential.fingerprint}
                            </small>
                        </div>
                        <CredentialUsedStateBadge {credential} />
                        <Button
                            variant="ghost"
                            size="compact"
                            onclick={() => (revoking = credential)}
                        >
                            Revoke
                        </Button>
                    </li>
                {/each}
            </ul>

            {#if c.certificates.length === 0 && c.credentialPolicy.kubernetes?.includes(CredentialKind.Certificate)}
                <Callout tone="warning" title="You need a certificate">
                    Your credential policy requires a certificate for Kubernetes
                    authentication. Without one you will not be able to sign in.
                </Callout>
            {/if}
        </section>

        {#if c.sso.length > 0}
            <section>
                <div class="section-head">
                    <h2>Single sign-on</h2>
                </div>
                <ul class="creds">
                    {#each c.sso as credential (credential.id)}
                        <li>
                            <span class="cred-label">
                                {credential.email}
                                {#if credential.provider}
                                    ({credential.provider})
                                {/if}
                            </span>
                        </li>
                    {/each}
                </ul>
            </section>
        {/if}
    {/if}
</Loadable>

{#if changingPassword}
    <CreatePasswordModal
        bind:isOpen={changingPassword}
        create={changePassword}
    />
{/if}

{#if creatingPublicKeyCredential}
    <PublicKeyCredentialModal
        bind:isOpen={creatingPublicKeyCredential}
        save={createPublicKey}
    />
{/if}

{#if creatingOtpCredential && $serverInfo?.username}
    <CreateOtpModal
        bind:isOpen={creatingOtpCredential}
        username={$serverInfo.username}
        create={createOtp}
    />
{/if}

{#if issuingCertificateCredential && $serverInfo?.username}
    <CertificateCredentialModal
        bind:isOpen={issuingCertificateCredential}
        save={issueCertificate}
        username={$serverInfo.username}
        onClose={() => {
            issuingCertificateCredential = false
        }}
    />
{/if}

<ConfirmDialog
    open={!!revoking}
    title="Revoke this certificate?"
    confirmLabel="Revoke"
    onconfirm={confirmRevoke}
    oncancel={() => (revoking = undefined)}
>
    {#if revoking}
        {@const r = revoking}
        <p class="panel">
            <strong>{r.label}</strong>
            stops working immediately and cannot be reinstated. Its private key
            is deleted from this browser at the same time, so anything using it
            — a kubeconfig, a script — will need a newly issued certificate.
        </p>
    {/if}
</ConfirmDialog>

<style>
    .notice {
        margin-bottom: var(--wg-space-lg);
    }

    section {
        margin-bottom: var(--wg-space-2xl);
    }

    .section-head {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: var(--wg-space-md);
        margin-bottom: var(--wg-space-sm);
    }

    h2 {
        margin: 0;
        font: var(--wg-text-headline-md);
    }

    .creds {
        list-style: none;
        margin: 0;
        padding: 0;
    }

    .creds li {
        display: flex;
        align-items: center;
        gap: var(--wg-space-md);
        padding: var(--wg-space-sm) 0;
        border-bottom: var(--wg-border-width) solid var(--wg-border);
        min-width: 0;
    }

    .creds li:last-child {
        border-bottom: 0;
    }

    .cred-main {
        display: flex;
        flex-direction: column;
        gap: 2px;
        min-width: 0;
        margin-right: auto;
    }

    .cred-label {
        margin-right: auto;
        font: var(--wg-text-body-md);
        overflow-wrap: anywhere;
    }

    .cred-main .cred-label {
        margin-right: 0;
    }

    .cred-sub {
        color: var(--wg-text-muted);
        font: var(--wg-text-code-sm);
        overflow-wrap: anywhere;
    }

    .panel {
        margin: 0;
        color: var(--wg-text-muted);
    }
</style>
