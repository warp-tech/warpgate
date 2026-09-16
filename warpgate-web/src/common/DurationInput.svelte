<script lang="ts">
    import { FormGroup, InputGroup } from '@sveltestrap/sveltestrap'

    import {
        DURATION_UNITS,
        humantimeDuration,
        bestDurationUnit,
    } from './duration'

    type Props = {
        label: string
        seconds: number | undefined
        onChange: (seconds: number | undefined) => void
        class?: string
    }

    let {
        label,
        seconds,
        onChange,
        class: className = 'mb-3',
    }: Props = $props()

    const inputId = $props.id()

    // svelte-ignore state_referenced_locally
    const unit = bestDurationUnit(seconds)

    // svelte-ignore state_referenced_locally
    let count = $state(
        unit && seconds != null ? seconds / unit.seconds : undefined,
    )
    let selectedUnit = $state(unit)

    // Every duration parameter the API takes has a minimum of one second, so a
    // count below one unit is not a shorter duration, it is an empty field.
    function emit() {
        if (count == null || count < 1 || !selectedUnit) {
            onChange(undefined)
        } else {
            onChange(Math.round(count * selectedUnit.seconds))
        }
    }
</script>

{#if unit}
    <InputGroup class={className}>
        <div class="form-floating">
            <input
                id={inputId}
                type="number"
                min="1"
                step="1"
                class="form-control"
                placeholder=" "
                bind:value={count}
                onchange={emit}
            >
            <label for={inputId}>{label}</label>
        </div>
        <select
            class="form-select"
            style="max-width: 120px"
            aria-label="Unit"
            bind:value={selectedUnit}
            onchange={emit}
        >
            {#each DURATION_UNITS as u (u.seconds)}
                <option value={u}>{u.label}</option>
            {/each}
        </select>
    </InputGroup>
{:else}
    <FormGroup floating {label} class={className}>
        <input
            type="text"
            class="form-control"
            placeholder="e.g. 1h 30m"
            use:humantimeDuration={{ seconds, onChange }}
        >
    </FormGroup>
{/if}
