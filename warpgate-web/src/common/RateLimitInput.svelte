<script lang="ts">
    import { Input, InputGroup } from '@sveltestrap/sveltestrap'

    type Props = {
        change?: CallableFunction
        value: number | undefined
        placeholder?: string
        allowEmpty?: boolean
    } & Input['$$prop_def']

    let {
        value = $bindable(),
        change,
        placeholder,
        allowEmpty = true,
        ...rest
    }: Props = $props()

    if (allowEmpty) {
        placeholder ??= 'Unlimited'
    }

    // Validation constants
    const minBytes = 100 * 1000 // 100 KB
    const maxBytes = 4 * 1000 * 1000 * 1000 // actually 4 GiB (u32) but here 4GB for nicer display

    // Unit conversion constants
    const units = [
        { label: 'KB', value: 1000, suffix: 'kilobytes' },
        { label: 'MB', value: 1000 * 1000, suffix: 'megabytes' },
        { label: 'GB', value: 1000 * 1000 * 1000, suffix: 'gigabytes' },
    ]

    // Internal state - these are completely separate from the external value
    let displayValue: number | undefined = $state()
    let selectedUnit = $state(units[0]!)
    let lastExternalValue: number | undefined = $state()

    function isValidValue (v: number | undefined): boolean {
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
            const unit = units[i]!
            if (bytes >= unit.value) {
                return unit
            }
        }
        return units[0]!
    }

    // Initialize display when external value changes (not internal changes)
    $effect(() => {
        // Only update if the value actually changed from outside
        if (value !== lastExternalValue) {
            lastExternalValue = value
            if (value !== undefined && value !== null) {
                // Auto-select best unit using helper function
                selectedUnit = getDisplayUnit(value)
                displayValue = value / selectedUnit.value
            } else {
                displayValue = undefined
                selectedUnit = units[0]!
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

    function maybeUpdateValue (v: number | undefined) {
        if (!isValidValue(v)) {
            return
        }
        value = v
        lastExternalValue = v // Prevent effect from re-running
        change?.()
    }
</script>

<InputGroup>
    <Input
        {...rest}
        type="number"
        min="0"
        step="any"
        bind:value={displayValue}
        on:change={handleChange}
        {placeholder}
        invalid={!isValid}
    />
    <Input
        type="select"
        class="form-select"
        feedback={feedbackMessage}
        bind:value={selectedUnit}
        onchange={handleChange}
        style="max-width: 100px;"
    >
        {#each units as unit (unit.value)}
            <option value={unit}>{unit.label}/s</option>
        {/each}
    </Input>
</InputGroup>
