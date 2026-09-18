<script lang="ts">
    /**
     * Create an admin role — restyled in place.
     *
     * Behaviour preserved: the role starts from emptyPermissions(), so a new
     * role grants nothing until permissions are ticked on the detail page, and
     * createAdminRole is followed by replace() to that page.
     */
    import { type AdminRole, api } from 'admin/lib/api'
    import PermissionGate from 'admin/lib/PermissionGate.svelte'
    import { stringifyError } from 'common/errors'
    import { replace } from 'svelte-spa-router'
    import Button from 'ui/Button.svelte'
    import Callout from 'ui/Callout.svelte'
    import Input from 'ui/Input.svelte'
    import 'ui/layout.css'
    import { emptyPermissions } from '../lib/store'

    let error: string | null = $state(null)
    let role: AdminRole = $state({
        id: '',
        name: '',
        description: '',
        ...emptyPermissions(),
    })

    async function create() {
        if (!role.name.trim()) {
            return
        }
        try {
            const r = await api.createAdminRole({ adminRoleDataRequest: role })
            replace(`/config/admin-roles/${r.id}`)
        } catch (err) {
            error = await stringifyError(err)
        }
    }
</script>

<PermissionGate
    perm="adminRolesManage"
    message="You have no permission to manage admin roles."
>
    <div class="wg-page-narrow">
        <div class="wg-page-head">
            <div>
                <h1>Create admin role</h1>
                <p class="wg-page-lede">
                    The new role grants nothing until you tick permissions on
                    the next screen.
                </p>
            </div>
        </div>

        {#if error}
            <div class="notice">
                <Callout tone="danger" title="Could not create the role">
                    {error}
                </Callout>
            </div>
        {/if}

        <form
            class="wg-field-stack"
            onsubmit={e => {
                e.preventDefault()
                create()
            }}
        >
            <Input label="Name" required autofocus bind:value={role.name} />
            <Input label="Description" bind:value={role.description} />
            <div class="actions">
                <Button
                    variant="primary"
                    type="submit"
                    disabled={!role.name.trim()}
                    click={create}
                >
                    Create
                </Button>
            </div>
        </form>
    </div>
</PermissionGate>

<style>
    .notice {
        margin-bottom: var(--wg-space-lg);
    }

    .actions {
        display: flex;
        justify-content: flex-end;
    }
</style>
