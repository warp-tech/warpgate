<script lang="ts">
    import { faIdBadge, faKey, faKeyboard, faMobileScreen } from '@fortawesome/free-solid-svg-icons'
    import { api, CredentialKind, type ExistingPasswordCredential, type ExistingSsoCredential, type User, type UserRequireCredentialsPolicy } from 'admin/lib/api'
    import AsyncButton from 'common/AsyncButton.svelte'
    import DelayedSpinner from 'common/DelayedSpinner.svelte'
    import Fa from 'svelte-fa'
    import { replace } from 'svelte-spa-router'
    import { Button, FormGroup, Input } from '@sveltestrap/sveltestrap'
    import AuthPolicyEditor from './AuthPolicyEditor.svelte'
    import UserCredentialModal from './UserCredentialModal.svelte'
    import { stringifyError } from 'common/errors'
    import Alert from 'common/Alert.svelte'
    import CreatePasswordModal from './CreatePasswordModal.svelte'
    import SsoCredentialModal from './SsoCredentialModal.svelte'

    type ExistingCredential =
        { kind: typeof CredentialKind.Password } & ExistingPasswordCredential
        | { kind: typeof CredentialKind.Sso } & ExistingSsoCredential

    interface Props {
        userId: string
    }
    let { userId }: Props = $props()

    let error: string|null = $state(null)
    let credentials: ExistingCredential[] = $state([])

    let creatingPassword = $state(false)
    let editingSsoCredential = $state(false)
    let editingSsoCredentialInstance: ExistingSsoCredential|null = $state(null)

    // let editingCredential: UserAuthCredential|undefined = $state()

    const loadPromise = load()

    async function load () {
        try {
            await Promise.all([
                loadPasswords(),
                loadSso(),
            ])
        } catch (err) {
            error = await stringifyError(err)
        }
    }

    async function loadPasswords () {
        credentials.push(...(await api.getPasswordCredentials({ userId })).map(c => ({
            kind: CredentialKind.Password,
            ...c,
        })))
    }

    async function loadSso () {
        credentials.push(...(await api.getSsoCredentials({ userId })).map(c => ({
            kind: CredentialKind.Sso,
            ...c,
        })))
    }

    async function deleteCredential (credential: ExistingCredential) {
        credentials = credentials.filter(c => c !== credential)
        if (credential.kind === CredentialKind.Password) {
            await api.deletePasswordCredential({
                id: credential.id,
                userId,
            })
        }
        if (credential.kind === CredentialKind.Sso) {
            await api.deleteSsoCredential({
                id: credential.id,
                userId,
            })
        }
    }

    async function createPassword (password: string) {
        const credential = await api.createPasswordCredential({
            userId,
            newPasswordCredential: {
                password,
            },
        })
        credentials.push({
            kind: CredentialKind.Password,
            ...credential,
        })
    }

    async function saveSsoCredential (provider: string|null, email: string) {
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
                newSsoCredential: {
                    provider:provider ?? undefined,
                    email,
                },
            })
            credentials.push({
                kind: CredentialKind.Sso,
                ...credential,
            })
        }
        editingSsoCredential = false
        editingSsoCredentialInstance = null
    }

    // function abbreviatePublicKey (key: string) {
    //     return key.slice(0, 16) + '...' + key.slice(-8)
    // }

    // function saveCredential () {
    //     if (!editingCredential || !user) {
    //         return
    //     }
    //     if (user.credentials.includes(editingCredential)) {
    //         user.credentials = [...user.credentials]
    //     } else {
    //         user.credentials.push(editingCredential)
    //         for (const protocol of ['http', 'ssh'] as ('http'|'ssh')[]) {
    //             for (const ck of [CredentialKind.Password, CredentialKind.PublicKey]) {
    //                 if (
    //                     editingCredential.kind === CredentialKind.Totp
    //                 && !user.credentialPolicy?.[protocol]
    //                 && user.credentials.some(x => x.kind === ck)
    //                 && possibleCredentials[protocol]?.has(ck)
    //                 ) {
    //                     user.credentialPolicy = {
    //                         ...user.credentialPolicy ?? {},
    //                         [protocol]: [ck, CredentialKind.Totp],
    //                     }
    //                     policy = user.credentialPolicy
    //                 }
    //             }
    //         }
    //     }
    //     editingCredential = undefined
    // }
</script>

<div class="d-flex align-items-center mt-4 mb-2">
    <h4 class="m-0">Credentials</h4>
    <span class="ms-auto"></span>
    <Button size="sm" color="link" on:click={() => creatingPassword = true}>
        Add password
    </Button>
    <!--
    <Button size="sm" color="link" on:click={() => editingCredential = {
        kind: 'PublicKey',
        key: '',
    }}>Add public key</Button>
    <Button size="sm" color="link" on:click={() => editingCredential = {
        kind: 'Totp',
        key: [],
    }}>Add OTP</Button>
-->
    <Button size="sm" color="link" on:click={() => {
        editingSsoCredentialInstance = null
        editingSsoCredential = true
    }}>Add SSO</Button>
</div>

{#await loadPromise}
<DelayedSpinner />
{:then}

<div class="list-group list-group-flush mb-3">
    {#each credentials as credential}
    <div class="list-group-item credential">
        {#if credential.kind === CredentialKind.Password }
            <Fa fw icon={faKeyboard} />
            <span class="type">Password</span>
        {/if}
        <!-- {#if credential.kind === 'PublicKey'}
            <Fa fw icon={faKey} />
            <span class="type">Public key</span>
            <span class="text-muted ms-2">{abbreviatePublicKey(credential.key)}</span>
        {/if}
        {#if credential.kind === 'Totp'}
            <Fa fw icon={faMobileScreen} />
            <span class="type">One-time password</span>
        {/if}
        -->
        {#if credential.kind === CredentialKind.Sso}
            <Fa fw icon={faIdBadge} />
            <span class="type">Single sign-on</span>
            <span class="text-muted ms-2">
                {credential.email}
                {#if credential.provider} ({credential.provider}){/if}
            </span>
        {/if}

        <span class="ms-auto"></span>
        {#if credential.kind !== CredentialKind.Password}
        <a
            class="ms-2"
            href={''}
            onclick={e => {
                if (credential.kind === CredentialKind.Sso) {
                    editingSsoCredentialInstance = credential
                    editingSsoCredential = true
                }
                e.preventDefault()
            }}>
            Change
        </a>
        {/if}
        <a
            class="ms-2"
            href={''}
            onclick={e => {
                deleteCredential(credential)
                e.preventDefault()
            }}>
            Delete
        </a>
    </div>
    {/each}
</div>

{/await}

{#if error}
    <Alert color="danger">{error}</Alert>
{/if}

<!-- {#if editingCredential}
<UserCredentialModal
    credential={editingCredential}
    username={user!.username}
    save={saveCredential}
    cancel={() => editingCredential = undefined}
/>
{/if} -->

{#if creatingPassword}
<CreatePasswordModal
    bind:isOpen={creatingPassword}
    create={createPassword}
/>
{/if}

{#if editingSsoCredential}
<SsoCredentialModal
    bind:isOpen={editingSsoCredential}
    instance={editingSsoCredentialInstance}
    save={saveSsoCredential}
/>
{/if}

<style lang="scss">
    .credential {
        display: flex;
        align-items: center;

        .type {
            margin-left: .5rem;
        }

        a {
            display: none;
        }

        &:hover a {
            display: initial;
        }
    }
</style>
