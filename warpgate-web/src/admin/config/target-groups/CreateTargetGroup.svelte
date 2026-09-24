<script lang="ts">
    /**
     * Add a target group — restyled in place.
     *
     * Behaviour preserved: name required with its own message, description and
     * colour both optional and sent as undefined when blank, the colour swatch
     * picker over VALID_CHOICES including the empty "None" choice, and
     * replace() to the list on success.
     *
     * The picker is a radiogroup now. It was a row of buttons with an `active`
     * class, which announced as six unrelated buttons with no indication of
     * which one was chosen — the selection was carried by a background colour
     * alone.
     */
    import { api, type BootstrapThemeColor } from 'admin/lib/api'
    import { stringifyError } from 'common/errors'
    import GroupColorIcon from 'common/GroupColorIcon.svelte'
    import { link, replace } from 'svelte-spa-router'
    import Button from 'ui/Button.svelte'
    import Callout from 'ui/Callout.svelte'
    import Input from 'ui/Input.svelte'
    import 'ui/layout.css'
    import Textarea from 'ui/Textarea.svelte'
    import { VALID_CHOICES } from './common'

    let name = $state('')
    let description = $state('')
    let color = $state<BootstrapThemeColor | ''>('')
    let error: string | undefined = $state()

    async function save() {
        if (!name.trim()) {
            error = 'Name is required'
            return
        }
        error = undefined
        try {
            await api.createTargetGroup({
                targetGroupDataRequest: {
                    name: name.trim(),
                    description: description.trim() || undefined,
                    color: color || undefined,
                },
            })
            replace('/config/target-groups')
        } catch (e) {
            error = await stringifyError(e)
            throw e
        }
    }
</script>

<div class="wg-page-narrow">
    <div class="wg-page-head">
        <h1>Add a target group</h1>
    </div>

    {#if error}
        <div class="notice">
            <Callout tone="danger" title="Could not create the group">
                {error}
            </Callout>
        </div>
    {/if}

    <form
        class="wg-field-stack"
        onsubmit={e => {
            e.preventDefault()
            save()
        }}
    >
        <Input label="Name" required autofocus bind:value={name} />

        <Textarea
            label="Description"
            rows={3}
            mono={false}
            spellcheck
            bind:value={description}
        />

        <fieldset class="colors">
            <legend>Colour</legend>
            <p class="hint">Optional, for visual organisation in lists.</p>
            <div class="swatches">
                {#each VALID_CHOICES as value (value)}
                    <label class="swatch" class:swatch-on={color === value}>
                        <input
                            type="radio"
                            name="group-color"
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
            <a class="cancel" href="/config/target-groups" use:link>Cancel</a>
            <Button
                variant="primary"
                type="submit"
                disabled={!name.trim()}
                click={save}
            >
                Create
            </Button>
        </div>
    </form>
</div>

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

    /* The radio stays in the accessibility tree and keeps arrow-key
       navigation; the label around it is the visible control. */
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
        justify-content: flex-end;
        gap: var(--wg-space-md);
        margin-top: var(--wg-space-md);
    }

    .cancel {
        color: var(--wg-text-muted);
        font: var(--wg-text-body-md);
    }

    .cancel:focus-visible {
        outline: var(--wg-focus-ring);
        outline-offset: var(--wg-focus-ring-offset);
    }
</style>
