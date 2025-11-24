<script lang="ts">
    import { api, BootstrapThemeColor, type TargetGroup } from 'admin/lib/api'
    import { link, replace } from 'svelte-spa-router'
    import { onMount } from 'svelte'
    import { Button, FormGroup, Input, Label, Alert } from '@sveltestrap/sveltestrap'
    import { stringifyError } from 'common/errors'
    import { VALID_CHOICES } from './common'
    import GroupColorCircle from 'common/GroupColorCircle.svelte'
    import AsyncButton from 'common/AsyncButton.svelte'

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
    let color = $state<BootstrapThemeColor | ''>('')

    onMount(async () => {
        try {
            group = await api.getTargetGroup({ id: groupId })
            name = group.name
            description = group.description
            color = group.color ?? ''
        } catch (e) {
            error = await stringifyError(e)
            console.error(e)
        } finally {
            loading = false
        }
    })

    async function save () {
        if (!group) {
            return
        }

        saving = true
        saveError = undefined

        try {
            await api.updateTargetGroup({
                id: groupId,
                targetGroupDataRequest: {
                    name,
                    description: description || undefined,
                    color: color || undefined,
                },
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
                <small class="form-text text-muted">
                    Optional Bootstrap theme color for visual organization
                </small>
                <div class="color-picker">
                    {#each VALID_CHOICES as value (value)}
                        <button
                            type="button"
                            class="btn btn-secondary gap-2 d-flex align-items-center"
                            class:active={color === value}
                            disabled={saving}
                            onclick={(e) => {
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
                <AsyncButton click={handleSubmit}>Save</AsyncButton>
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
</style>
