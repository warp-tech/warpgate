<script lang="ts">
    /**
     * Target group detail — restyled in place.
     *
     * Behaviour preserved: fields seeded from the loaded group, blank
     * description and colour sent as undefined rather than empty strings,
     * saving disabling the form, Update gated on targetsEdit and Remove on
     * targetsDelete, and replace() to the list after deletion.
     *
     * The window.confirm becomes a typed ConfirmDialog. Deleting a group is
     * the irreversible-consequence-the-dialog-cannot-show-you case: the
     * targets in it are not listed here, and they lose their grouping without
     * appearing anywhere on this screen.
     *
     * The colour picker becomes a radiogroup, same as on the create screen —
     * it was a row of buttons whose selection was a background colour alone.
     */
    import {
        api,
        type BootstrapThemeColor,
        type TargetGroup,
    } from 'admin/lib/api'
    import { adminPermissions } from 'admin/lib/store'
    import { stringifyError } from 'common/errors'
    import GroupColorIcon from 'common/GroupColorIcon.svelte'
    import Loadable from 'common/Loadable.svelte'
    import { replace } from 'svelte-spa-router'
    import Button from 'ui/Button.svelte'
    import Callout from 'ui/Callout.svelte'
    import ConfirmDialog from 'ui/ConfirmDialog.svelte'
    import Input from 'ui/Input.svelte'
    import 'ui/layout.css'
    import Textarea from 'ui/Textarea.svelte'
    import { VALID_CHOICES } from './common'

    interface Props {
        params: { id: string }
    }

    let { params }: Props = $props()
    const groupId = $derived(params.id)

    let group: TargetGroup | undefined = $state()
    let error: string | undefined = $state()
    let saving = $state(false)
    let removing = $state(false)

    let name = $state('')
    let description = $state('')
    let color = $state<BootstrapThemeColor | ''>('')

    const initPromise = init()

    async function init() {
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

    async function update() {
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

    async function confirmRemove() {
        try {
            await api.deleteTargetGroup({ id: groupId })
            replace('/config/target-groups')
        } catch (e) {
            error = await stringifyError(e)
        } finally {
            removing = false
        }
    }
</script>

{#if error}
    <div class="notice">
        <Callout tone="danger" title="Something went wrong">{error}</Callout>
    </div>
{/if}

<Loadable promise={initPromise}>
    {#if group}
        {@const g = group}
        <div class="wg-page-narrow">
            <div class="wg-page-head">
                <div>
                    <h1>{g.name}</h1>
                    <p class="wg-page-lede">Target group</p>
                </div>
            </div>

            <form
                class="wg-field-stack"
                onsubmit={e => {
                    e.preventDefault()
                    update()
                }}
            >
                <Input
                    label="Name"
                    required
                    disabled={saving}
                    bind:value={name}
                />

                <Textarea
                    label="Description"
                    rows={3}
                    mono={false}
                    spellcheck
                    disabled={saving}
                    bind:value={description}
                />

                <fieldset class="colors">
                    <legend>Colour</legend>
                    <p class="hint">
                        Optional, for visual organisation in lists.
                    </p>
                    <div class="swatches">
                        {#each VALID_CHOICES as value (value)}
                            <label
                                class="swatch"
                                class:swatch-on={color === value}
                            >
                                <input
                                    type="radio"
                                    name="group-color"
                                    disabled={saving}
                                    checked={color === value}
                                    onchange={() => (color = value)}
                                >
                                <GroupColorIcon color={value} />
                                <span>{value || 'None'}</span>
                            </label>
                        {/each}
                    </div>
                </fieldset>

                <div class="actions">
                    <Button
                        variant="destructive"
                        disabled={!$adminPermissions.targetsDelete}
                        onclick={() => (removing = true)}
                    >
                        Remove
                    </Button>
                    <Button
                        variant="primary"
                        type="submit"
                        disabled={!$adminPermissions.targetsEdit}
                        click={update}
                    >
                        Update
                    </Button>
                </div>
            </form>
        </div>

        <ConfirmDialog
            bind:open={removing}
            title="Delete {g.name}?"
            confirmLabel="Delete group"
            confirmText={g.name}
            confirmTextLabel="group name"
            onconfirm={confirmRemove}
            oncancel={() => (removing = false)}
        >
            <p class="panel">
                The targets in this group are not deleted, but they lose their
                grouping, and this screen does not list them — so there is no
                way to see from here how many are affected.
            </p>
        </ConfirmDialog>
    {/if}
</Loadable>

<style>
    .notice {
        margin-bottom: var(--wg-space-lg);
    }

    .colors {
        margin: 0;
        padding: 0;
        border: 0;
    }

    legend {
        padding: 0;
        font: var(--wg-text-body-md);
        color: var(--wg-text-muted);
    }

    .hint {
        margin: 0 0 var(--wg-space-sm);
        font: var(--wg-text-label-sm);
        color: var(--wg-text-subtle);
    }

    .swatches {
        display: flex;
        flex-wrap: wrap;
        gap: var(--wg-space-sm);
    }

    .swatch {
        display: inline-flex;
        align-items: center;
        gap: var(--wg-space-sm);
        padding: var(--wg-space-xs) var(--wg-space-sm);
        background: var(--wg-surface-container);
        border: var(--wg-border-width) solid var(--wg-border-strong);
        border-radius: var(--wg-radius-control);
        font: var(--wg-text-label-md);
        cursor: pointer;
    }

    .swatch:hover {
        background: var(--wg-surface-container-high);
    }

    .swatch-on {
        border-color: var(--wg-primary);
        background: var(--wg-surface-container-highest);
    }

    .swatch input {
        position: absolute;
        width: 1px;
        height: 1px;
        opacity: 0;
    }

    .swatch:has(input:focus-visible) {
        outline: var(--wg-focus-ring);
        outline-offset: var(--wg-focus-ring-offset);
    }

    .actions {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: var(--wg-space-md);
        margin-top: var(--wg-space-lg);
    }

    .panel {
        margin: 0;
        color: var(--wg-text-muted);
    }
</style>
