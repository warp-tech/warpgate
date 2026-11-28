<script lang="ts">
    import { Alert, Form, FormGroup } from '@sveltestrap/sveltestrap'
    import { api } from 'admin/lib/api'
    import PermissionGate from 'admin/lib/PermissionGate.svelte'
    import AsyncButton from 'common/AsyncButton.svelte'
    import { stringifyError } from 'common/errors'
    import OnboardingHint from 'common/OnboardingHint.svelte'
    import { replace } from 'svelte-spa-router'
    import { adminPermissions } from '../lib/store'

    let error: string | null = $state(null)
    let username = $state('')

    async function create() {
        try {
            const user = await api.createUser({
                createUserRequest: {
                    username,
                },
            })
            replace(`/manage/users/${user.id}`)
        } catch (err) {
            error = await stringifyError(err)
        }
    }
</script>

<PermissionGate
    perm="usersCreate"
    message="You have no permission to create users."
>
    <div class="container-max-md">
        {#if error}
            <Alert color="danger">{error}</Alert>
        {/if}

        <div class="page-summary-bar">
            <h1>add a user</h1>
        </div>

        <OnboardingHint>
            Add a second, non-admin user that can only access targets you have
            defined and not this admin interface
        </OnboardingHint>

        <div class="narrow-page">
            <Form>
                <FormGroup floating label="Username">
                    <input class="form-control" required bind:value={username}>
                </FormGroup>

                <AsyncButton
                    color="primary"
                    click={create}
                    disabled={!$adminPermissions.usersCreate}
                >
                    Create user
                </AsyncButton>
            </Form>
        </div>
    </div>
</PermissionGate>
