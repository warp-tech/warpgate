<script lang="ts">
    import { api, type TargetGroupDataRequest } from 'admin/lib/api'
    import { link, replace } from 'svelte-spa-router'
    import { Button, FormGroup, Input, Label, Alert } from '@sveltestrap/sveltestrap'
    import { stringifyError } from 'common/errors'

    let name = $state('')
    let description = $state('')
    let color = $state('')
    let saving = $state(false)
    let error: string | undefined = $state()

    const VALID_COLORS = ['primary', 'secondary', 'success', 'danger', 'warning', 'info', 'light', 'dark']

    function capitalizeFirst(str: string): string {
        return str.charAt(0).toUpperCase() + str.slice(1).toLowerCase()
    }

    function getValidColor(colorValue: string): string | undefined {
        const trimmed = colorValue.trim().toLowerCase()
        if (!trimmed) return undefined
        if (VALID_COLORS.includes(trimmed)) {
            return capitalizeFirst(trimmed) as any
        }
        return undefined
    }

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
                    color: getValidColor(color),
                }
            })
            // Redirect to groups list
            replace('/config/target-groups')
        } catch (e) {
            error = await stringifyError(e)
            console.error(e)
        } finally {
            saving = false
        }
    }

    function handleSubmit (e: SubmitEvent) {
        e.preventDefault()
        save()
    }
</script>

<div class="container-max-md">
    <div class="page-summary-bar">
        <h1>Create target group</h1>
    </div>

    {#if error}
        <Alert color="danger">{error}</Alert>
    {/if}

    <form onsubmit={handleSubmit}>
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
                type="select"
                bind:value={color}
                disabled={saving}
            >
                <option value="">None</option>
                <option value="primary">Primary</option>
                <option value="secondary">Secondary</option>
                <option value="success">Success</option>
                <option value="danger">Danger</option>
                <option value="warning">Warning</option>
                <option value="info">Info</option>
                <option value="light">Light</option>
                <option value="dark">Dark</option>
            </Input>
            <small class="form-text text-muted">
                Optional Bootstrap theme color for visual organization
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
