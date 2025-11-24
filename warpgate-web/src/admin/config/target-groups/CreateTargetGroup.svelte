<script lang="ts">
    import { api, type BootstrapThemeColor } from 'admin/lib/api'
    import { link, replace } from 'svelte-spa-router'
    import { Button, FormGroup, Input, Label, Alert } from '@sveltestrap/sveltestrap'
    import { stringifyError } from 'common/errors'
    import GroupColorCircle from 'common/GroupColorCircle.svelte'
    import { VALID_CHOICES } from './common';

    let name = $state('')
    let description = $state('')
    let color = $state<BootstrapThemeColor | ''>('')
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
                    color: color || undefined,
                },
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
            <small class="form-text text-muted">
                Optional theme color for visual organization
            </small>
            <div class="color-picker">
                {#each VALID_CHOICES as value (value)}
                    <button
                        type="button"
                        class="btn btn-secondary"
                        class:active={color === value}
                        disabled={saving}
                        onclick={e => {
                            e.preventDefault()
                            color = value
                        }}
                        title={value || 'None'}
                    >
                        <GroupColorCircle color={value} />
                        <span>{value || 'None'}</span>
                    </button>
                {/each}
            </div>
        </FormGroup>

        <div class="d-flex gap-2 mt-5">
            <Button type="submit" color="primary" disabled={saving}>
                {saving ? 'Creating...' : 'Create'}
            </Button>
            <a class="btn btn-secondary" href="/config/target-groups" use:link>
                Cancel
            </a>
        </div>
    </form>
</div>

<style lang="scss">
    .color-picker {
        display: flex;
        flex-wrap: wrap;
        gap: 0.5rem;

        > button {
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
    }
</style>
