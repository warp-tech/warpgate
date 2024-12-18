<script lang="ts">
    import { api, CredentialKind, PasswordState, type CredentialsState, type ExistingOtpCredential, type ExistingPublicKeyCredential } from 'gateway/lib/api'
    import { serverInfo } from 'gateway/lib/store'
    import DelayedSpinner from 'common/DelayedSpinner.svelte'
    import Alert from 'common/Alert.svelte'
    import { stringifyError } from 'common/errors'
    import { faIdBadge, faKey, faKeyboard, faMobilePhone } from '@fortawesome/free-solid-svg-icons'
    import Fa from 'svelte-fa'
    import PublicKeyCredentialModal from 'admin/PublicKeyCredentialModal.svelte'
    import { Button } from '@sveltestrap/sveltestrap'
    import CreatePasswordModal from 'admin/CreatePasswordModal.svelte'
    import CreateOtpModal from 'admin/CreateOtpModal.svelte'

    let error: string|null = $state(null)
    let creds: CredentialsState | undefined = $state()

    let creatingPublicKeyCredential = $state(false)
    let creatingOtpCredential = $state(false)
    let changingPassword = $state(false)

    async function load () {
        try {
            creds = await api.getMyCredentials()
        } catch (err) {
            error = await stringifyError(err)
        }
    }

    async function changePassword (password: string) {
        const state = await api.changeMyPassword({ changePasswordRequest: { password } })
        creds!.password = state
    }

    async function createPublicKey (label: string, opensshPublicKey: string) {
        const credential = await api.addMyPublicKey({
            newPublicKeyCredential: {
                label,
                opensshPublicKey,
            },
        })
        creds!.publicKeys.push(credential)
    }

    async function deletePublicKey (credential: ExistingPublicKeyCredential) {
        creds!.publicKeys = creds!.publicKeys.filter(c => c.id !== credential.id)
        await api.deleteMyPublicKey(credential)
    }

    async function createOtp (secretKey: number[]) {
        const credential = await api.addMyOtp({
            newOtpCredential: {
                secretKey,
            },
        })
        creds!.otp.push(credential)
    }

    async function deleteOtp (credential: ExistingOtpCredential) {
        creds!.otp = creds!.otp.filter(c => c.id !== credential.id)
        await api.deleteMyOtp(credential)
    }
</script>

{#await load()}
    <DelayedSpinner />
{:then}
{#if creds}
    <div class="d-flex align-items-center mt-4 mb-2">
        <h4 class="m-0">Password</h4>
    </div>

    <div class="list-group list-group-flush mb-3">
        <div class="list-group-item credential">
            {#if creds.password === PasswordState.Unset}
                <span class="label">Your account has no password set</span>
            {/if}
            {#if creds.password === PasswordState.Set}
                <Fa fw icon={faKeyboard} />
                <span class="label">Password set</span>
            {/if}
            {#if creds.password === PasswordState.MultipleSet}
                <Fa fw icon={faKeyboard} />
                <span class="label">Multiple passwords set</span>
            {/if}

            <span class="ms-auto"></span>
            <a
                class="ms-2"
                href={''}
                onclick={e => {
                    changingPassword = true
                    e.preventDefault()
                }}>
                {#if creds.password === PasswordState.Unset}
                    Set password
                {/if}
                {#if creds.password === PasswordState.Set}
                    Change
                {/if}
                {#if creds.password === PasswordState.MultipleSet}
                    Reset password
                {/if}
            </a>
        </div>
    </div>

    {#if creds.publicKeys.length === 0 && Object.values(creds.credentialPolicy).some(l => l?.includes(CredentialKind.Password))}
        <Alert color="warning">
            Your credential policy requires using a password for authentication. Without one, you won't be able to log in.
        </Alert>
    {/if}

    <div class="d-flex align-items-center mt-4 mb-2">
        <h4 class="m-0">One-time passwords</h4>
        <span class="ms-auto"></span>
        <Button size="sm" color="link" on:click={() => {
            creatingOtpCredential = true
        }}>Add device</Button>
    </div>

    <div class="list-group list-group-flush mb-3">
        {#each creds.otp as credential}
        <div class="list-group-item credential">
            <Fa fw icon={faMobilePhone} />
            <span class="label">OTP device</span>
            <span class="ms-auto"></span>
            <a
                class="hover-reveal ms-2"
                href={''}
                onclick={e => {
                    deleteOtp(credential)
                    e.preventDefault()
                }}
            >
                Delete
            </a>
        </div>
        {/each}
    </div>

    {#if creds.otp.length === 0 && Object.values(creds.credentialPolicy).some(l => l?.includes(CredentialKind.Totp))}
        <Alert color="warning">
            Your credential policy requires using a one-time password for authentication. Without one, you won't be able to log in.
        </Alert>
    {/if}

    <div class="d-flex align-items-center mt-4 mb-2">
        <h4 class="m-0">Public keys</h4>
        <span class="ms-auto"></span>
        <Button size="sm" color="link" on:click={() => {
            creatingPublicKeyCredential = true
        }}>Add new</Button>
    </div>

    <div class="list-group list-group-flush mb-3">
        {#each creds.publicKeys as credential}
        <div class="list-group-item credential">
            <Fa fw icon={faKey} />
            <div class="key-info">
                <div>
                    <span class="label">{credential.label}</span>
                    <span class="text-muted ms-2">{credential.abbreviated}</span>
                </div>
                {#if credential.dateAdded}
                    <div class="added-info">Added On: {new Date(credential.dateAdded).toLocaleString()}</div>
                {/if}
            </div>
            <span class="ms-auto"></span>
            <a
                class="hover-reveal ms-2"
                href={''}
                onclick={e => {
                    deletePublicKey(credential);
                    e.preventDefault();
                }}
            >
                Delete
            </a>
        </div>
        {/each}
    </div>

    {#if creds.publicKeys.length === 0 && creds.credentialPolicy.ssh?.includes(CredentialKind.PublicKey)}
        <Alert color="warning">
            Your credential policy requires using a public key for authentication. Without one, you won't be able to log in.
        </Alert>
    {/if}

    {#if creds.sso.length > 0}
    <div class="d-flex align-items-center mt-4 mb-2">
        <h4 class="m-0">Single sign-on</h4>
    </div>

    <div class="list-group list-group-flush mb-3">
        {#each creds.sso as credential}
        <div class="list-group-item credential">
            <Fa fw icon={faIdBadge} />
            <span class="label">
                {credential.email}
                {#if credential.provider} ({credential.provider}){/if}
            </span>
        </div>
        {/each}
    </div>
    {/if}
{/if}
{/await}

{#if error}
<Alert color="danger">{error}</Alert>
{/if}

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

{#if creatingOtpCredential}
<CreateOtpModal
    bind:isOpen={creatingOtpCredential}
    username={$serverInfo!.username!}
    create={createOtp}
/>
{/if}

<style lang="scss">
    .credential {
        display: flex;
        align-items: flex-start; // Align items at the top
        .key-info {
            display: flex;
            flex-direction: column; // Stack label, key, and date vertically
            margin-left: 0.5rem;

            .added-info {
                font-size: 0.9rem; // Smaller font for subtlety
                color: #6c757d; // Optional: A lighter muted color
                margin-top: 0.25rem; // Add some spacing between the key and the date
            }
        }

        .label:not(:first-child) {
            margin-left: .5rem;
        }

        a.hover-reveal {
            display: none;
        }

        &:hover a {
            display: initial;
        }
    }
</style>
