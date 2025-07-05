<script lang="ts">
    import { api, CredentialKind, PasswordState, type CredentialsState, type ExistingOtpCredential, type ExistingPublicKeyCredential } from 'gateway/lib/api'
    import { serverInfo } from 'gateway/lib/store'
    import Alert from 'common/sveltestrap-s5-ports/Alert.svelte'
    import { faIdBadge, faKey, faKeyboard, faMobilePhone } from '@fortawesome/free-solid-svg-icons'
    import Fa from 'svelte-fa'
    import PublicKeyCredentialModal from 'admin/PublicKeyCredentialModal.svelte'
    import CreatePasswordModal from 'admin/CreatePasswordModal.svelte'
    import CreateOtpModal from 'admin/CreateOtpModal.svelte'
    import CredentialUsedStateBadge from 'common/CredentialUsedStateBadge.svelte'
    import Loadable from 'common/Loadable.svelte'
    import { Button } from '@sveltestrap/sveltestrap'

    let creds: CredentialsState | undefined = $state()

    let creatingPublicKeyCredential = $state(false)
    let creatingOtpCredential = $state(false)
    let changingPassword = $state(false)

    const initPromise = init()

    async function init () {
        creds = await api.getMyCredentials()
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

<Loadable promise={initPromise}>
{#if creds}
    <div class="d-flex align-items-center mt-4 mb-2">
        <h4 class="m-0">Password</h4>
    </div>

    <div class="list-group list-group-flush mb-3">
        <div class="list-group-item credential">
            {#if creds.password === PasswordState.Unset}
                <span class="label ms-3">Your account has no password set</span>
            {/if}
            {#if creds.password === PasswordState.Set}
                <Fa fw icon={faKeyboard} />
                <span class="label ms-3">Password set</span>
            {/if}
            {#if creds.password === PasswordState.MultipleSet}
                <Fa fw icon={faKeyboard} />
                <span class="label ms-3">Multiple passwords set</span>
            {/if}

            <span class="ms-auto"></span>
            <Button
                class="ms-2"
                color="link"
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
            </Button>
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
        <Button color="link" onclick={e => {
            creatingOtpCredential = true
            e.preventDefault()
        }}>Add device</Button>
    </div>

    <div class="list-group list-group-flush mb-3">
        {#each creds.otp as credential (credential.id)}
        <div class="list-group-item credential">
            <Fa fw icon={faMobilePhone} />
            <span class="label ms-3">OTP device</span>
            <span class="ms-auto"></span>
            <Button
                class="ms-2"
                color="link"
                onclick={e => {
                    deleteOtp(credential)
                    e.preventDefault()
                }}
            >
                Delete
            </Button>
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
        <Button color="link" onclick={e => {
            creatingPublicKeyCredential = true
            e.preventDefault()
        }}>Add key</Button>
    </div>

    <div class="list-group list-group-flush mb-3">
        {#each creds.publicKeys as credential (credential.id)}
        <div class="list-group-item credential">
            <Fa fw icon={faKey} />
            <div class="main ms-3">
                <div class="label">{credential.label}</div>
                <small class="d-block text-muted">{credential.abbreviated}</small>
            </div>
            <span class="ms-auto"></span>
            <CredentialUsedStateBadge credential={credential} />
            <Button
            class="ms-2"
                color="link"
                onclick={e => {
                    deletePublicKey(credential)
                    e.preventDefault()
                }}
            >
                Delete
            </Button>
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
        {#each creds.sso as credential (credential.id)}
        <div class="list-group-item credential">
            <Fa fw icon={faIdBadge} />
            <span class="label ms-3">
                {credential.email}
                {#if credential.provider} ({credential.provider}){/if}
            </span>
        </div>
        {/each}
    </div>
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
        align-items: center;
        padding-left: 0;
        padding-right: 0;
    }
</style>
