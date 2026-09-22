<script lang="ts">
    /**
     * A duration as a count plus a unit — "30 minutes" rather than a free-text
     * "30m" that the user has to know the spelling of.
     *
     * Upstream added this component in #2602 and converted eleven fields on
     * the global parameters screen to it. That version is built on
     * sveltestrap's FormGroup and InputGroup, which this fork has removed, so
     * it is redrawn here on ui/Input and ui/Select. Same props, same
     * behaviour, same two branches — only the primitives differ, so a future
     * merge touches the call sites and not the contract.
     *
     * The `{:else}` branch is load-bearing, not a nicety: bestDurationUnit
     * returns undefined for a value that would carry awkwardly into a larger
     * unit (say 90 minutes, which is neither a whole number of hours nor
     * naturally read as minutes), and those fall back to the free-text
     * humantime input that can express anything.
     *
     * This docblock sits above the imports with a blank line under it on
     * purpose. Biome's import sorter treats a comment attached to the first
     * import as part of it and carries it down the list when it re-sorts.
     */

    import Input from 'ui/Input.svelte'
    import Select from 'ui/Select.svelte'
    import {
        bestDurationUnit,
        DURATION_UNITS,
        humantimeDuration,
    } from './duration'

    type Props = {
        label: string
        seconds: number | undefined
        onChange: (seconds: number | undefined) => void
        class?: string
    }

    let { label, seconds, onChange, class: className = '' }: Props = $props()

    // Read once. This picks the unit the field OPENS with; re-deriving it
    // while someone types would swap the unit under them mid-edit.
    // svelte-ignore state_referenced_locally
    const unit = bestDurationUnit(seconds)

    // svelte-ignore state_referenced_locally
    let count = $state(
        unit && seconds != null ? String(seconds / unit.seconds) : '',
    )
    let unitSeconds = $state(unit?.seconds ?? 60)

    const unitOptions = DURATION_UNITS.map(u => ({
        value: u.seconds,
        label: u.label,
    }))

    // Every duration parameter the API takes has a minimum of one second, so a
    // count below one unit is not a shorter duration, it is an empty field.
    function emit() {
        const n = Number(count)
        if (!count.trim() || !Number.isFinite(n) || n < 1) {
            onChange(undefined)
        } else {
            onChange(Math.round(n * unitSeconds))
        }
    }
</script>

{#if unit}
    <div class="wg-duration {className}">
        <Input
            {label}
            type="number"
            min={1}
            inputmode="numeric"
            bind:value={count}
            oninput={emit}
        />
        <Select
            label="Unit"
            labelHidden
            options={unitOptions}
            bind:value={unitSeconds}
            onchange={emit}
        />
    </div>
{:else}
    <label class="wg-field-group {className}">
        <span class="wg-field-label">{label}</span>
        <input
            type="text"
            class="form-control"
            placeholder="e.g. 1h 30m"
            use:humantimeDuration={{ seconds, onChange }}
        >
    </label>
{/if}

<style>
    .wg-duration {
        display: flex;
        /* The count carries a label and the unit does not, so their boxes only
           line up if the row is anchored at the bottom. */
        align-items: flex-end;
        gap: var(--wg-space-sm);
    }

    /* The children are components, so their roots never carry this file's
       scope hash. The combinator stays outside :global() — `:global(> *)` is
       not a selector. */
    .wg-duration > :global(*:first-child) {
        flex: 1 1 auto;
        min-width: 0;
    }

    .wg-duration > :global(*:last-child) {
        flex: 0 0 8rem;
    }
</style>
