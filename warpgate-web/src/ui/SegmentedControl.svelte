<script lang="ts" module>
    export interface Segment<T extends string> {
        value: T
        label: string
        disabled?: boolean
    }
</script>

<script lang="ts" generics="T extends string">
    /**
     * NET-NEW primitive.
     *
     * A small set of mutually exclusive choices, all visible at once — table
     * density, player speed, a two-way filter. It is a radio group, not a
     * tablist: it picks a value, it does not swap a panel. Use Tabs for that.
     *
     * Implemented with real radio inputs so arrow-key navigation, form
     * participation and the "one tab stop for the whole group" behaviour come
     * from the platform rather than from hand-rolled key handlers.
     */
    interface Props {
        value?: T
        segments: Segment<T>[]
        /** The group's accessible name. Required — a bare group announces nothing. */
        label: string
        labelHidden?: boolean
        disabled?: boolean
        size?: 'standard' | 'compact'
        name?: string
        class?: string
        onchange?: (value: T) => void
    }

    let {
        value = $bindable(),
        segments,
        label,
        labelHidden = true,
        disabled = false,
        size = 'standard',
        name = `wg-seg-${Math.random().toString(36).slice(2, 9)}`,
        class: className = '',
        onchange,
    }: Props = $props()

    function select(v: T) {
        value = v
        onchange?.(v)
    }
</script>

<fieldset class="wg-seg-field {className}" {disabled}>
    <legend class:wg-sr-only={labelHidden}>{label}</legend>
    <div class="wg-seg wg-seg-{size}">
        {#each segments as segment (segment.value)}
            <label
                class="wg-seg-item"
                class:wg-seg-active={value === segment.value}
                class:wg-seg-disabled={segment.disabled}
            >
                <input
                    type="radio"
                    {name}
                    value={segment.value}
                    checked={value === segment.value}
                    disabled={segment.disabled}
                    onchange={() => select(segment.value)}
                >
                <span>{segment.label}</span>
            </label>
        {/each}
    </div>
</fieldset>

<style>
    .wg-seg-field {
        margin: 0;
        padding: 0;
        border: 0;
        min-inline-size: 0;
    }

    legend {
        padding: 0;
        margin-bottom: var(--wg-space-xs);
        font: var(--wg-text-body-md);
        color: var(--wg-text-muted);
    }

    .wg-seg {
        display: inline-flex;
        border: var(--wg-border-width) solid var(--wg-border-strong);
        border-radius: var(--wg-radius-control);
        overflow: hidden;
        background: var(--wg-surface-container);
    }

    .wg-seg-item {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        height: calc(var(--wg-control-height) - 2px);
        padding: 0 var(--wg-control-padding-x);
        font: var(--wg-text-label-md);
        color: var(--wg-text-muted);
        cursor: pointer;
        transition:
            background var(--wg-duration-fast) var(--wg-easing),
            color var(--wg-duration-fast) var(--wg-easing);
    }

    .wg-seg-compact .wg-seg-item {
        height: calc(var(--wg-control-height-compact) - 2px);
        padding: 0 var(--wg-control-padding-x-compact);
        font: var(--wg-text-label-sm);
    }

    /* Divider between segments, not around them */
    .wg-seg-item + .wg-seg-item {
        border-left: var(--wg-border-width) solid var(--wg-border);
    }

    .wg-seg-item:hover:not(.wg-seg-disabled):not(.wg-seg-active) {
        background: var(--wg-surface-container-high);
        color: var(--wg-text);
    }

    .wg-seg-active {
        background: var(--wg-primary);
        color: var(--wg-on-primary);
    }

    .wg-seg-disabled {
        opacity: 0.45;
        cursor: not-allowed;
    }

    /* Native radio stays focusable and keyboard-operable; only its paint
     * is replaced, so arrow-key traversal is the browser's, not ours. */
    input {
        position: absolute;
        opacity: 0;
        width: 0;
        height: 0;
    }

    .wg-seg-item:has(input:focus-visible) {
        outline: var(--wg-focus-ring);
        outline-offset: calc(-1 * var(--wg-focus-ring-width));
    }

    .wg-seg-field:disabled .wg-seg {
        opacity: 0.45;
    }

    .wg-sr-only {
        position: absolute;
        width: 1px;
        height: 1px;
        padding: 0;
        margin: -1px;
        overflow: hidden;
        clip-path: inset(50%);
        white-space: nowrap;
        border: 0;
    }
</style>
