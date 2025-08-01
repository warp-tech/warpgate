<script lang="ts">
    import { api, type Role, type User } from 'admin/lib/api'
    import AsyncButton from 'common/AsyncButton.svelte'
    import { replace } from 'svelte-spa-router'
    import { FormGroup, Input } from '@sveltestrap/sveltestrap'
    import { stringifyError } from 'common/errors'
    import Alert from 'common/sveltestrap-s5-ports/Alert.svelte'
    import CredentialEditor from '../CredentialEditor.svelte'
    import Loadable from 'common/Loadable.svelte'
    import RateLimitInput from 'common/RateLimitInput.svelte'

    interface Props {
        params: { id: string };
    }

    let { params }: Props = $props()

    let error: string|null = $state(null)
    let user: User | undefined = $state()
    let allRoles: Role[] = $state([])
    let roleIsAllowed: Record<string, any> = $state({})

    const initPromise = init()

    async function init () {
        user = await api.getUser({ id: params.id })
        user.credentialPolicy ??= {}

        allRoles = await api.getRoles()
        const allowedRoles = await api.getUserRoles(user)
        roleIsAllowed = Object.fromEntries(allowedRoles.map(r => [r.id, true]))
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
            replace('/config/users')
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
</script>

<div class="container-max-md">
    <Loadable promise={initPromise}>
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

    <FormGroup floating label="Description">
        <Input bind:value={user.description} />
    </FormGroup>

    <CredentialEditor
        userId={user.id}
        username={user.username}
        bind:credentialPolicy={user.credentialPolicy!}
    />

    <h4 class="mt-4">User roles</h4>
    <div class="list-group list-group-flush mb-3">
        {#each allRoles as role (role.id)}
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
                <div>
                    <div>{role.name}</div>
                    {#if role.description}
                        <small class="text-muted">{role.description}</small>
                    {/if}
                </div>
            </label>
        {/each}
    </div>

    <h4 class="mt-4">Traffic</h4>
    <FormGroup floating label="User bandwidth limit">
        <RateLimitInput
            bind:value={user.rateLimitBytesPerSecond}
            change={update}
        />
    </FormGroup>
    {/if}
    </Loadable>

    {#if error}
        <Alert color="danger">{error}</Alert>
    {/if}

    <div class="d-flex">
        <AsyncButton
        color="primary"
            class="ms-auto"
            click={update}
        >Update</AsyncButton>

        <AsyncButton
            class="ms-2"
            color="danger"
            click={remove}
        >Remove</AsyncButton>
    </div>
</div>
