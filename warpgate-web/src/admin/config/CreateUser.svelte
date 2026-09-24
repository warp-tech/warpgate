<script lang="ts">
    /**
     * Add a user — restyled in place.
     *
     * Behaviour preserved: createUser then replace() to the detail page, and
     * usersCreate gating both the warning and the button.
     */
    import { api } from 'admin/lib/api'
    import { stringifyError } from 'common/errors'
    import { replace } from 'svelte-spa-router'
    import Button from 'ui/Button.svelte'
    import Callout from 'ui/Callout.svelte'
    import Input from 'ui/Input.svelte'
    import 'ui/layout.css'
    import { adminPermissions } from '../lib/store'

    let error: string | null = $state(null)
    let username = $state('')

    async function create() {
        if (!username.trim()) {
            return
        }
        try {
            const user = await api.createUser({
                createUserRequest: { username },
            })
            replace(`/config/users/${user.id}`)
        } catch (err) {
            error = await stringifyError(err)
        }
    }
</script>

<div class="wg-page-narrow">
    <div class="wg-page-head">
        <h1>Add a user</h1>
    </div>

    {#if !$adminPermissions.usersCreate}
        <div class="notice">
            <Callout tone="warning" title="Not available to your role">
                You do not have permission to create users.
            </Callout>
        </div>
    {/if}

    {#if error}
        <div class="notice">
            <Callout tone="danger" title="Could not create the user">
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
        <Input
            label="Username"
            required
            autofocus
            disabled={!$adminPermissions.usersCreate}
            bind:value={username}
        />
        <div class="actions">
            <Button
                variant="primary"
                type="submit"
                disabled={!$adminPermissions.usersCreate || !username.trim()}
                click={create}
            >
                Create user
            </Button>
        </div>
    </form>
</div>

<style>
    .notice {
        margin-bottom: var(--wg-space-lg);
    }

    .actions {
        display: flex;
        justify-content: flex-end;
    }
</style>
