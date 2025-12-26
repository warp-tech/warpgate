<script lang="ts">
    import { api, type Role, type User } from 'admin/lib/api'
    import { serverInfo } from 'gateway/lib/store'
    import AsyncButton from 'common/AsyncButton.svelte'
    import { replace } from 'svelte-spa-router'
    import { Dropdown, DropdownItem, DropdownMenu, DropdownToggle, FormGroup, Input } from '@sveltestrap/sveltestrap'
    import { stringifyError } from 'common/errors'
    import Alert from 'common/sveltestrap-s5-ports/Alert.svelte'
    import CredentialEditor from '../CredentialEditor.svelte'
    import Loadable from 'common/Loadable.svelte'
    import RateLimitInput from 'common/RateLimitInput.svelte'
    import Fa from 'svelte-fa'
    import { faCaretDown, faLink, faUnlink } from '@fortawesome/free-solid-svg-icons'

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

    async function unlinkFromLdap () {
        try {
            user = await api.unlinkUserFromLdap({ id: params.id })
            error = null
        } catch (err) {
            error = await stringifyError(err)
        }
    }

    async function autoLinkToLdap () {
        try {
            user = await api.autoLinkUserToLdap({ id: params.id })
            error = null
        } catch (err) {
            error = await stringifyError(err)
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

    <div class="d-flex align-items-center gap-3">
        <FormGroup floating label="Username" class="flex-grow-1">
            <Input bind:value={user.username} disabled={!user.ldapServerId} />
        </FormGroup>

        {#if $serverInfo?.hasLdap}
        <Dropdown class="mb-3">
            <DropdownToggle color={user.ldapServerId ? 'info' : 'secondary'} class="d-flex align-items-center gap-2">
                {#if user.ldapServerId}
                    <Fa icon={faLink} fw />
                {/if}
                LDAP
                <Fa icon={faCaretDown} />
            </DropdownToggle>
            <DropdownMenu right={true}>
                {#if user.ldapServerId}
                <DropdownItem on:click={unlinkFromLdap}>
                    <Fa icon={faUnlink} fw />
                    Unlink from LDAP
                </DropdownItem>
                {:else}
                <DropdownItem on:click={autoLinkToLdap}>
                    <Fa icon={faLink} fw />
                    Auto-link to LDAP
                </DropdownItem>
                {/if}
            </DropdownMenu>
        </Dropdown>
        {/if}
    </div>

    <FormGroup floating label="Description">
        <Input bind:value={user.description} />
    </FormGroup>

    <CredentialEditor
        userId={user.id}
        username={user.username}
        bind:credentialPolicy={user.credentialPolicy!}
        ldapLinked={!!user.ldapServerId}
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
    <FormGroup class="mb-5">
        <label for="rateLimitBytesPerSecond">Global bandwidth limit</label>
        <RateLimitInput
            id="rateLimitBytesPerSecond"
            bind:value={user.rateLimitBytesPerSecond}
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
