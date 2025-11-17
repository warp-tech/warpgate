<script lang="ts">
    import { api, type TargetGroup, type TargetGroupDataRequest } from 'admin/lib/api'
    import { link, replace } from 'svelte-spa-router'
    import { onMount } from 'svelte'
    import { Button, FormGroup, Input, Label, Alert } from '@sveltestrap/sveltestrap'
    import { stringifyError } from 'common/errors'

    interface Props {
        params: { id: string };
    }

    let { params }: Props = $props()
    let groupId = params.id

    let group: TargetGroup | undefined = $state()
    let loading = $state(true)
    let error: string | undefined = $state()
    let saving = $state(false)
    let saveError: string | undefined = $state()

    let name = $state('')
    let description = $state('')
    let color = $state('')

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

    onMount(async () => {
        try {
            group = await api.getTargetGroup({ id: groupId })
            name = group.name
            description = group.description
            // Convert capitalized API value to lowercase for form
            // Only use valid colors, ignore any invalid values
            const apiColor = group.color ? group.color.toLowerCase() : ''
            color = VALID_COLORS.includes(apiColor) ? apiColor : ''
        } catch (e) {
            error = await stringifyError(e)
            console.error(e)
        } finally {
            loading = false
        }
    })

    async function save () {
        if (!group) return

        saving = true
        saveError = undefined

        try {
            await api.updateTargetGroup({
                id: groupId,
                targetGroupDataRequest: {
                    name,
                    description: description || undefined,
                    color: getValidColor(color),
                }
            })
            // Redirect to groups list after successful save
            replace('/config/target-groups')
        } catch (e) {
            saveError = await stringifyError(e)
            console.error(e)
        } finally {
            saving = false
        }
    }

    function handleSubmit (e: SubmitEvent) {
        e.preventDefault()
        save()
    }

    async function deleteGroup () {
        if (!group || !confirm(`Are you sure you want to delete the group "${group.name}"?`)) {
            return
        }

        try {
            await api.deleteTargetGroup({ id: groupId })
            // Redirect to groups list
            replace('/config/target-groups')
        } catch (e) {
            saveError = await stringifyError(e)
            console.error('Delete target group error:', e)
        }
    }
</script>

{#if loading}
    <div class="d-flex justify-content-center p-4">
        <div class="spinner-border" role="status">
            <span class="visually-hidden">Loading...</span>
        </div>
    </div>
{:else if error}
    <Alert color="danger">{error}</Alert>
{:else if group}
    <div class="container-max-md">
        <div class="page-summary-bar">
            <h1>Edit target group</h1>
            <div class="ms-auto">
                <Button color="danger" onclick={deleteGroup}>Delete</Button>
            </div>
        </div>

        {#if saveError}
            <Alert color="danger">{saveError}</Alert>
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
                <div class="color-picker">
                    <button
                        type="button"
                        class="color-option"
                        class:selected={color === ''}
                        disabled={saving}
                        onclick={(e) => {
                            e.preventDefault()
                            color = ''
                        }}
                        title="None"
                    >
                        <span class="color-circle" style="background-color: transparent; border: 1px solid var(--bs-border-color);"></span>
                        <span>None</span>
                    </button>
                    {#each VALID_COLORS as colorName}
                        <button
                            type="button"
                            class="color-option"
                            class:selected={color === colorName}
                            disabled={saving}
                            onclick={(e) => {
                                e.preventDefault()
                                color = colorName
                            }}
                            title={capitalizeFirst(colorName)}
                        >
                            <span class="color-circle" style={`background-color: var(--bs-${colorName});`}></span>
                            <span>{capitalizeFirst(colorName)}</span>
                        </button>
                    {/each}
                </div>
                <small class="form-text text-muted">
                    Optional Bootstrap theme color for visual organization
                </small>
            </FormGroup>

            <div class="d-flex gap-2">
                <Button type="submit" color="primary" disabled={saving}>
                    {saving ? 'Saving...' : 'Save'}
                </Button>
                <a class="btn btn-secondary" href="/config/target-groups" use:link>
                    Cancel
                </a>
            </div>
        </form>
    </div>
{/if}

<style lang="scss">
    .color-picker {
        display: flex;
        flex-wrap: wrap;
        gap: 0.5rem;
    }

    .color-option {
        display: flex;
        align-items: center;
        gap: 0.5rem;
        padding: 0.5rem 0.75rem;
        border: 1px solid var(--bs-border-color);
        background-color: var(--bs-body-bg);
        color: var(--bs-body-color);
        border-radius: 0.375rem;
        cursor: pointer;
        transition: all 0.15s ease-in-out;

        &:hover:not(:disabled) {
            background-color: var(--bs-secondary-bg);
            border-color: var(--bs-primary);
        }

        &:disabled {
            opacity: 0.6;
            cursor: not-allowed;
        }

        &.selected {
            border-color: var(--bs-primary);
            background-color: var(--bs-primary-bg-subtle);
        }

        .color-circle {
            display: inline-block;
            width: 16px;
            height: 16px;
            border-radius: 50%;
            flex-shrink: 0;
        }
    }
</style>
