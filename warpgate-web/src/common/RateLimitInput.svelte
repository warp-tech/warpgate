<script lang="ts">
    import Input from 'ui/Input.svelte'
    import Select from 'ui/Select.svelte'

    type Props = {
        change?: CallableFunction
        value: number | undefined
        placeholder?: string
        allowEmpty?: boolean
        label?: string
        disabled?: boolean
        /** Callers label this field externally and point at it. */
        id?: string
    }

    let {
        value = $bindable(),
        change,
        placeholder,
        allowEmpty = true,
        label = 'Rate limit',
        disabled = false,
        id,
    }: Props = $props()

    // svelte-ignore state_referenced_locally
    if (allowEmpty) {
        placeholder ??= 'Unlimited'
    }

    // Validation constants
    const minBytes = 100 * 1000 // 100 KB
    const maxBytes = 4 * 1000 * 1000 * 1000 // actually 4 GiB (u32) but here 4GB for nicer display

    // Unit conversion constants
    interface Unit {
        label: string
        value: number
        suffix: string
    }
    const units: [Unit, Unit, Unit] = [
        { label: 'KB', value: 1000, suffix: 'kilobytes' },
        { label: 'MB', value: 1000 * 1000, suffix: 'megabytes' },
        { label: 'GB', value: 1000 * 1000 * 1000, suffix: 'gigabytes' },
    ]

    // Internal state - these are completely separate from the external value
    let displayValue: number | undefined = $state()
    // ui/Select is a real <select>, which carries strings. The original bound
    // whole objects to <option value={unit}>, which only works because Svelte
    // keeps a reference map.
    let selectedUnitLabel: string = $state(units[0].label)
    const selectedUnit = $derived(
        units.find(u => u.label === selectedUnitLabel) ?? units[0],
    )
    let lastExternalValue: number | undefined = $state()

    function isValidValue(v: number | undefined): boolean {
        if (v === undefined) {
            return allowEmpty
        }
        return v >= minBytes && v <= maxBytes
    }

    // Validation logic
    const isValid = $derived.by(() => isValidValue(toBytes()))

    // Generate feedback message
    const feedbackMessage = $derived.by(() => {
        const minUnit = getDisplayUnit(minBytes)
        const maxUnit = getDisplayUnit(maxBytes)
        const minDisplay = (minBytes / minUnit.value).toFixed(0)
        const maxDisplay = (maxBytes / maxUnit.value).toFixed(0)

        let msg = `Value must be between ${minDisplay} ${minUnit.label} and ${maxDisplay} ${maxUnit.label}.`
        if (allowEmpty) {
            msg += ' Leave empty for no limit.'
        }
        return msg
    })

    // Helper function to get best display unit for a byte value
    function getDisplayUnit(bytes: number) {
        for (let i = units.length - 1; i >= 0; i--) {
            const unit = units[i]
            if (unit && bytes >= unit.value) {
                return unit
            }
        }
        return units[0]
    }

    // Initialize display when external value changes (not internal changes)
    $effect(() => {
        // Only update if the value actually changed from outside
        if (value !== lastExternalValue) {
            lastExternalValue = value
            if (value !== undefined && value !== null) {
                // Auto-select best unit using helper function
                const unit = getDisplayUnit(value)
                selectedUnitLabel = unit.label
                displayValue = value / unit.value
            } else {
                displayValue = undefined
                selectedUnitLabel = units[0].label
            }
        }
    })

    // Convert display value to bytes
    function toBytes(): number | undefined {
        if (displayValue === undefined || displayValue === null) {
            return undefined
        }
        return Math.round(displayValue * selectedUnit.value)
    }

    function handleChange() {
        maybeUpdateValue(toBytes())
    }

    function maybeUpdateValue(v: number | undefined) {
        if (!isValidValue(v)) {
            return
        }
        value = v
        lastExternalValue = v // Prevent effect from re-running
        change?.()
    }
</script>

<div class="rate-limit">
    <div class="rate-value">
        <Input
            {id}
            {label}
            labelHidden
            type="number"
            min="0"
            inputmode="decimal"
            {placeholder}
            {disabled}
            value={displayValue === undefined ? '' : String(displayValue)}
            invalid={!isValid}
            error={isValid ? undefined : feedbackMessage}
            oninput={e => {
                const raw = (e.target as HTMLInputElement).value
                displayValue = raw === '' ? undefined : Number(raw)
                handleChange()
            }}
        />
    </div>
    <div class="rate-unit">
        <Select
            label="Rate limit unit"
            labelHidden
            size="compact"
            {disabled}
            bind:value={selectedUnitLabel}
            options={units.map(u => ({ value: u.label, label: `${u.label}/s` }))}
            onchange={handleChange}
        />
    </div>
</div>

<style>
    .rate-limit {
        display: flex;
        align-items: flex-start;
        gap: var(--wg-space-sm);
    }

    .rate-value {
        flex: 1 1 auto;
        min-width: 0;
    }

    .rate-unit {
        flex: none;
        width: 7rem;
    }
</style>
