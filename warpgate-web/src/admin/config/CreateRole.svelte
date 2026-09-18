<script lang="ts">
    /**
     * Add an access role — restyled in place.
     *
     * Behaviour preserved: createRole with isDefault false, then replace() to
     * the new role's detail page so Back does not return to an empty form.
     */
    import { api } from 'admin/lib/api'
    import { stringifyError } from 'common/errors'
    import { replace } from 'svelte-spa-router'
    import Button from 'ui/Button.svelte'
    import Callout from 'ui/Callout.svelte'
    import Input from 'ui/Input.svelte'
    import 'ui/layout.css'

    let error: string | null = $state(null)
    let name = $state('')

    async function create() {
        if (!name.trim()) {
            return
        }
        try {
            const role = await api.createRole({
                roleDataRequest: { name, isDefault: false },
            })
            replace(`/config/access-roles/${role.id}`)
        } catch (err) {
            error = await stringifyError(err)
        }
    }
</script>

<div class="wg-page-narrow">
    <div class="wg-page-head">
        <h1>Add a role</h1>
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
        <Input label="Name" required autofocus bind:value={name} />
        <div class="actions">
            <Button
                variant="primary"
                type="submit"
                disabled={!name.trim()}
                click={create}
            >
                Create role
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
