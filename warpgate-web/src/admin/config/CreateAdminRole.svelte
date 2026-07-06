<script lang="ts">
    import { Alert, FormGroup, Input } from '@sveltestrap/sveltestrap'
    import { type AdminRole, api } from 'admin/lib/api'
    import PermissionGate from 'admin/lib/PermissionGate.svelte'
    import AsyncButton from 'common/AsyncButton.svelte'
    import { stringifyError } from 'common/errors'
    import { replace } from 'svelte-spa-router'
    import { emptyPermissions } from '../lib/store'

    let error: string | null = $state(null)
    let role: AdminRole = $state({
        id: '',
        name: '',
        description: '',
        ...emptyPermissions(),
    })

    async function create() {
        try {
            const r = await api.createAdminRole({ adminRoleDataRequest: role })
            replace(`/config/admin-roles/${r.id}`)
        } catch (err) {
            error = await stringifyError(err)
        }
    }
</script>

<div class="container-max-md">
    <PermissionGate
        perm="adminRolesManage"
        message="You have no permission to manage admin roles."
    >
        <div class="page-summary-bar">
            <h1>create admin role</h1>
        </div>

        <div class="narrow-page">
            <FormGroup floating label="Name">
                <Input bind:value={role.name} autofocus />
            </FormGroup>

            <FormGroup floating label="Description">
                <Input bind:value={role.description} />
            </FormGroup>

            {#if error}
                <Alert color="danger">{error}</Alert>
            {/if}

            <div class="d-flex mt-3">
                <AsyncButton color="primary" class="ms-auto" click={create}
                    >Create</AsyncButton
                >
            </div>
        </div>
    </PermissionGate>
</div>
