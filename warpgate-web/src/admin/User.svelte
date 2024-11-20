<script lang="ts">
    import { api, type Role, type User, type UserRequireCredentialsPolicy } from 'admin/lib/api'
    import AsyncButton from 'common/AsyncButton.svelte'
    import DelayedSpinner from 'common/DelayedSpinner.svelte'
    import { replace } from 'svelte-spa-router'
    import { FormGroup, Input } from '@sveltestrap/sveltestrap'
    import AuthPolicyEditor from './AuthPolicyEditor.svelte'
    import { stringifyError } from 'common/errors'
    import Alert from 'common/Alert.svelte'
    import CredentialEditor from './CredentialEditor.svelte'
    import { possibleCredentials } from 'common/protocols'

    interface Props {
        params: { id: string };
    }

    let { params }: Props = $props()

    let error: string|null = $state(null)
    let user: User | undefined = $state()
    let policy: UserRequireCredentialsPolicy | undefined = $state()
    let allRoles: Role[] = $state([])
    let roleIsAllowed: Record<string, any> = $state({})

    const policyProtocols: { id: 'ssh' | 'http' | 'mysql' | 'postgres', name: string }[] = [
        { id: 'ssh', name: 'SSH' },
        { id: 'http', name: 'HTTP' },
        { id: 'mysql', name: 'MySQL' },
        { id: 'postgres', name: 'PostgreSQL' },
    ]

    async function load () {
        try {
            user = await api.getUser({ id: params.id })
            policy = user.credentialPolicy ?? {}
            user.credentialPolicy = policy

            allRoles = await api.getRoles()
            const allowedRoles = await api.getUserRoles(user)
            roleIsAllowed = Object.fromEntries(allowedRoles.map(r => [r.id, true]))
        } catch (err) {
            error = await stringifyError(err)
        }
    }

    async function update () {
        try {
            user = await api.updateUser({
                id: params.id,
                userDataRequest: user!,
            })
        } catch (err) {
            error = await stringifyError(err)
        }
    }

    async function remove () {
        if (confirm(`Delete user ${user!.username}?`)) {
            await api.deleteUser(user!)
            replace('/config')
        }
    }

    async function toggleRole (role: Role) {
        if (roleIsAllowed[role.id]) {
            await api.deleteUserRole({
                id: user!.id,
                roleId: role.id,
            })
            roleIsAllowed = { ...roleIsAllowed, [role.id]: false }
        } else {
            await api.addUserRole({
                id: user!.id,
                roleId: role.id,
            })
            roleIsAllowed = { ...roleIsAllowed, [role.id]: true }
        }
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
{#if user}
<div class="page-summary-bar">
    <div>
        <h1>{user.username}</h1>
        <div class="text-muted">User</div>
    </div>
</div>

<FormGroup floating label="Username">
    <Input bind:value={user.username} />
</FormGroup>

<CredentialEditor userId={user.id} />

<h4>Auth policy</h4>
<div class="list-group list-group-flush mb-3">
    {#each policyProtocols as protocol}
    <div class="list-group-item">
        <div>
            <strong>{protocol.name}</strong>
        </div>
        {#if possibleCredentials[protocol.id]}
        {@const _possibleCredentials = assertDefined(possibleCredentials[protocol.id])}
        <!-- <AuthPolicyEditor
            user={user}
            bind:value={policy!}
            possibleCredentials={_possibleCredentials}
            protocolId={protocol.id}
        /> -->
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
            on:change={() => toggleRole(role)}
            checked={roleIsAllowed[role.id]} />
            <div>{role.name}</div>
        </label>
    {/each}
</div>
{/if}
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
