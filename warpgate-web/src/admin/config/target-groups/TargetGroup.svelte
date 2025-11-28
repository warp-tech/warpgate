<script lang="ts">
    import { api, BootstrapThemeColor, type TargetGroup } from 'admin/lib/api'
    import { Button, FormGroup, Input, Label, Alert } from '@sveltestrap/sveltestrap'
    import { stringifyError } from 'common/errors'
    import { VALID_CHOICES } from './common'
    import GroupColorCircle from 'common/GroupColorCircle.svelte'
    import AsyncButton from 'common/AsyncButton.svelte'
    import Loadable from 'common/Loadable.svelte'

    interface Props {
        params: { id: string };
    }

    let { params }: Props = $props()
    let groupId = params.id

    let group: TargetGroup | undefined = $state()
    let error: string | undefined = $state()
    let saving = $state(false)

    let name = $state('')
    let description = $state('')
    let color = $state<BootstrapThemeColor | ''>('')

    const initPromise = init()

    async function init () {
        try {
            group = await api.getTargetGroup({ id: groupId })
            name = group.name
            description = group.description
            color = group.color ?? ''
        } catch (e) {
            error = await stringifyError(e)
            throw e
        }
    }

    async function update () {
        if (!group) {
            return
        }

        saving = true
        error = undefined

        try {
            await api.updateTargetGroup({
                id: groupId,
                targetGroupDataRequest: {
                    name,
                    description: description || undefined,
                    color: color || undefined,
                },
            })
        } catch (e) {
            error = await stringifyError(e)
            throw e
        } finally {
            saving = false
        }
    }

    async function remove () {
        if (!group || !confirm(`Delete target group "${group.name}"?`)) {
            return
        }

        try {
            await api.deleteTargetGroup({ id: groupId })
            // Redirect to groups list
            replace('/config/target-groups')
        } catch (e) {
            error = await stringifyError(e)
            throw e
        }
    }
</script>


{#if error}
    <Alert color="danger">{error}</Alert>
{/if}
<Loadable promise={initPromise}>
{#if group}
    <div class="container-max-md">
        <div class="page-summary-bar">
            <div>
                <h1>{group.name}</h1>
                <div class="text-muted">Target group</div>
            </div>
        </div>

        <form onsubmit={e => {
            e.preventDefault()
            update()
        }}>
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
                <AsyncButton click={update} color="primary">Update</AsyncButton>
                <Button color="danger" onclick={remove}>Remove</Button>
            </div>
        </form>
    </div>
{/if}
</Loadable>

<style lang="scss">
    .color-picker {
        display: flex;
        flex-wrap: wrap;
        gap: 0.5rem;
    }
</style>
