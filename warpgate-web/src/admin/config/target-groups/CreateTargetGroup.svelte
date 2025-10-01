<script lang="ts">
    import { api, type TargetGroupDataRequest } from 'admin/lib/api'
    import { link, replace } from 'svelte-spa-router'
    import { Button, FormGroup, Input, Label, Alert } from '@sveltestrap/sveltestrap'

    let name = $state('')
    let description = $state('')
    let color = $state('')
    let saving = $state(false)
    let error: string | undefined = $state()

    async function save () {
        if (!name.trim()) {
            error = 'Name is required'
            return
        }

        saving = true
        error = undefined

        try {
            await api.createTargetGroup({
                targetGroupDataRequest: {
                    name: name.trim(),
                    description: description.trim() || undefined,
                    color: color.trim() || undefined,
                }
            })
            // Redirect to groups list
            replace('/config/target-groups')
        } catch (e) {
            error = 'Failed to create target group'
            console.error(e)
        } finally {
            saving = false
        }
    }
</script>

<div class="container-max-md">
    <div class="page-summary-bar">
        <h1>Create target group</h1>
    </div>

    {#if error}
        <Alert color="danger">{error}</Alert>
    {/if}

    <form on:submit|preventDefault={save}>
        <FormGroup>
            <Label for="name">Name</Label>
            <Input
                id="name"
                bind:value={name}
                required
                disabled={saving}
            />
        </FormGroup>

        <FormGroup>
            <Label for="description">Description</Label>
            <Input
                id="description"
                type="textarea"
                bind:value={description}
                disabled={saving}
            />
        </FormGroup>

        <FormGroup>
            <Label for="color">Color</Label>
            <Input
                id="color"
                type="color"
                bind:value={color}
                disabled={saving}
            />
            <small class="form-text text-muted">
                Optional color for visual organization
            </small>
        </FormGroup>

        <div class="d-flex gap-2">
            <Button type="submit" color="primary" disabled={saving}>
                {saving ? 'Creating...' : 'Create'}
            </Button>
            <a class="btn btn-secondary" href="/config/target-groups" use:link>
                Cancel
            </a>
        </div>
    </form>
</div>
