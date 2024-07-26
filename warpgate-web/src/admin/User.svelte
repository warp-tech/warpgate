<script lang="ts">
import { faIdBadge, faKey, faKeyboard, faMobileScreen } from '@fortawesome/free-solid-svg-icons'
import { api, CredentialKind, type Role, type User, type UserAuthCredential, type UserRequireCredentialsPolicy } from 'admin/lib/api'
import AsyncButton from 'common/AsyncButton.svelte'
import DelayedSpinner from 'common/DelayedSpinner.svelte'
import Fa from 'svelte-fa'
import { replace } from 'svelte-spa-router'
import { Alert, Button, FormGroup, Input } from '@sveltestrap/sveltestrap'
import AuthPolicyEditor from './AuthPolicyEditor.svelte'
import UserCredentialModal from './UserCredentialModal.svelte'

export let params: { id: string }

let error: Error|undefined
let user: User
let editingCredential: UserAuthCredential|undefined
let policy: UserRequireCredentialsPolicy
let allRoles: Role[] = []
let roleIsAllowed: Record<string, any> = {}

const policyProtocols: { id: 'ssh' | 'http' | 'mysql', name: string }[] = [
    { id: 'ssh', name: 'SSH' },
    { id: 'http', name: 'HTTP' },
    { id: 'mysql', name: 'MySQL' },
]

const possibleCredentials: Record<string, Set<CredentialKind>> = {
    ssh: new Set([CredentialKind.Password, CredentialKind.PublicKey, CredentialKind.Totp, CredentialKind.WebUserApproval]),
    http: new Set([CredentialKind.Password, CredentialKind.Totp, CredentialKind.Sso]),
    mysql: new Set([CredentialKind.Password]),
}

async function load () {
    try {
        user = await api.getUser({ id: params.id })
        policy = user.credentialPolicy ?? {}
        user.credentialPolicy = policy

        allRoles = await api.getRoles()
        const allowedRoles = await api.getUserRoles(user)
        roleIsAllowed = Object.fromEntries(allowedRoles.map(r => [r.id, true]))
    } catch (err) {
        error = err as Error
    }
}

function deleteCredential (credential: UserAuthCredential) {
    user.credentials = user.credentials.filter(c => c !== credential)
}

function abbreviatePublicKey (key: string) {
    return key.slice(0, 16) + '...' + key.slice(-8)
}

async function update () {
    try {
        user = await api.updateUser({
            id: params.id,
            userDataRequest: user,
        })
    } catch (err) {
        error = err as Error
    }
}

async function remove () {
    if (confirm(`Delete user ${user.username}?`)) {
        await api.deleteUser(user)
        replace('/config')
    }
}

async function toggleRole (role: Role) {
    if (roleIsAllowed[role.id]) {
        await api.deleteUserRole({
            id: user.id,
            roleId: role.id,
        })
        roleIsAllowed = { ...roleIsAllowed, [role.id]: false }
    } else {
        await api.addUserRole({
            id: user.id,
            roleId: role.id,
        })
        roleIsAllowed = { ...roleIsAllowed, [role.id]: true }
    }
}

function saveCredential () {
    if (!editingCredential) {
        return
    }
    if (user.credentials.includes(editingCredential)) {
        user.credentials = [...user.credentials]
    } else {
        user.credentials.push(editingCredential)
        for (const protocol of ['http', 'ssh'] as ('http'|'ssh')[]) {
            for (const ck of [CredentialKind.Password, CredentialKind.PublicKey]) {
                if (
                    editingCredential.kind === CredentialKind.Totp
                    && !user.credentialPolicy?.[protocol]
                    && user.credentials.some(x => x.kind === ck)
                    && possibleCredentials[protocol]?.has(ck)
                ) {
                    user.credentialPolicy = {
                        ...user.credentialPolicy ?? {},
                        [protocol]: [ck, CredentialKind.Totp],
                    }
                    policy = user.credentialPolicy
                }
            }
        }
    }
    editingCredential = undefined
}

function assertDefined<T>(value: T|undefined): T {
    if (value === undefined) {
        throw new Error('Value is undefined')
    }
    return value
}
</script>

{#await load()}
    <DelayedSpinner />
{:then}
    <div class="page-summary-bar">
        <div>
            <h1>{user.username}</h1>
            <div class="text-muted">User</div>
        </div>
    </div>

    <FormGroup floating label="Username">
        <Input bind:value={user.username} />
    </FormGroup>

    <div class="d-flex align-items-center mt-4 mb-2">
        <h4 class="m-0">Credentials</h4>
        <span class="ms-auto"></span>
        <Button size="sm" color="link" on:click={() => editingCredential = {
            kind: 'Password',
            hash: '',
        }}>Add password</Button>
        <Button size="sm" color="link" on:click={() => editingCredential = {
            kind: 'PublicKey',
            key: '',
        }}>Add public key</Button>
        <Button size="sm" color="link" on:click={() => editingCredential = {
            kind: 'Totp',
            key: [],
        }}>Add OTP</Button>
        <Button size="sm" color="link" on:click={() => editingCredential = {
            kind: 'Sso',
            email: '',
        }}>Add SSO</Button>
    </div>

    <div class="list-group list-group-flush mb-3">
        {#each user.credentials as credential}
            <div class="list-group-item credential">
                {#if credential.kind === 'Password'}
                    <Fa fw icon={faKeyboard} />
                    <span class="type">Password</span>
                {/if}
                {#if credential.kind === 'PublicKey'}
                    <Fa fw icon={faKey} />
                    <span class="type">Public key</span>
                    <span class="text-muted ms-2">{abbreviatePublicKey(credential.key)}</span>
                {/if}
                {#if credential.kind === 'Totp'}
                    <Fa fw icon={faMobileScreen} />
                    <span class="type">One-time password</span>
                {/if}
                {#if credential.kind === 'Sso'}
                    <Fa fw icon={faIdBadge} />
                    <span class="type">Single sign-on</span>
                    <span class="text-muted ms-2">
                        {credential.email}
                        {#if credential.provider} ({credential.provider}){/if}
                    </span>
                {/if}

                <span class="ms-auto"></span>
                <a
                    class="ms-2"
                    href={''}
                    on:click|preventDefault={() =>
                        editingCredential = credential
                    }>
                    Change
                </a>
                <a
                    class="ms-2"
                    href={''}
                    on:click|preventDefault={() => deleteCredential(credential)}>
                    Delete
                </a>
            </div>
        {/each}
    </div>

    <h4>Auth policy</h4>
    <div class="list-group list-group-flush mb-3">
        {#each policyProtocols as protocol}
            <div class="list-group-item">
                <div>
                    <strong>{protocol.name}</strong>
                </div>
                {#if possibleCredentials[protocol.id]}
                    {@const _possibleCredentials = assertDefined(possibleCredentials[protocol.id])}
                    <AuthPolicyEditor
                        user={user}
                        bind:value={policy}
                        possibleCredentials={_possibleCredentials}
                        protocolId={protocol.id}
                    />
                {/if}
            </div>
        {/each}
    </div>

    <h4 class="mt-4">User roles</h4>
    <div class="list-group list-group-flush mb-3">
        {#each allRoles as role}
            <label
                for="role-{role.id}"
                class="list-group-item list-group-item-action d-flex align-items-center"
            >
                <Input
                    id="role-{role.id}"
                    class="mb-0 me-2"
                    type="switch"
                    on:click={() => toggleRole(role)}
                    checked={roleIsAllowed[role.id]} />
                <div>{role.name}</div>
            </label>
        {/each}
    </div>

{/await}

{#if error}
    <Alert color="danger">{error}</Alert>
{/if}

<div class="d-flex">
    <AsyncButton
        class="ms-auto"
        outline
        click={update}
    >Update</AsyncButton>

    <AsyncButton
        class="ms-2"
        outline
        color="danger"
        click={remove}
    >Remove</AsyncButton>
</div>

{#if editingCredential}
<UserCredentialModal
    credential={editingCredential}
    username={user.username}
    save={saveCredential}
    cancel={() => editingCredential = undefined}
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
