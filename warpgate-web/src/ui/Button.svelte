<script lang="ts" module>
    export type ButtonVariant =
        | 'primary'
        | 'secondary'
        | 'destructive'
        | 'ghost'
    export type ButtonSize = 'standard' | 'compact'
</script>

<script lang="ts">
    import type { Snippet } from 'svelte'
    import { AsyncAction, AsyncState } from './asyncAction.svelte'
    import Spinner from './Spinner.svelte'

    interface Props {
        variant?: ButtonVariant
        size?: ButtonSize
        type?: 'button' | 'submit' | 'reset'
        disabled?: boolean
        /** Renders at full container width. */
        block?: boolean
        /**
         * An icon-only button has no visible text, so it must be given a name
         * some other way. Required when `children` renders no text.
         */
        label?: string
        /**
         * Async handler. Providing it opts the button into the progress /
         * done / failed state machine; a plain `onclick` does not.
         */
        click?: () => unknown | Promise<unknown>
        onclick?: (event: MouseEvent) => void
        class?: string
        id?: string
        children?: Snippet
    }

    let {
        variant = 'secondary',
        size = 'standard',
        type = 'button',
        disabled = false,
        block = false,
        label,
        click,
        onclick,
        class: className = '',
        id,
        children,
    }: Props = $props()

    const action = new AsyncAction()
    let element: HTMLButtonElement | undefined = $state()

    async function handleClick(event: MouseEvent) {
        if (click) {
            event.preventDefault()
            await action.run(element, click)
            return
        }
        onclick?.(event)
    }

    const showLabel = $derived(
        action.state === AsyncState.Normal ||
            action.state === AsyncState.Progress,
    )
</script>

<button
    bind:this={element}
    {id}
    {type}
    class="wg-btn wg-btn-{variant} wg-btn-{size} {className}"
    class:wg-btn-block={block}
    class:wg-btn-busy={action.busy}
    style={action.lastWidth ? action.sizeStyle : undefined}
    disabled={disabled || action.busy}
    aria-label={label}
    aria-busy={action.busy}
    onclick={handleClick}
>
    {#if showLabel}
        {@render children?.()}
    {/if}

    {#if !showLabel}
        <span class="wg-btn-overlay">
            {#if action.state === AsyncState.ProgressWithSpinner}
                <Spinner size={size === 'compact' ? 12 : 14} />
            {:else if action.state === AsyncState.Done}
                <!-- Check -->
                <svg
                    viewBox="0 0 16 16"
                    width="14"
                    height="14"
                    aria-hidden="true"
                >
                    <path
                        d="M3 8.5l3.5 3.5L13 5"
                        fill="none"
                        stroke="currentColor"
                        stroke-width="2"
                        stroke-linecap="round"
                        stroke-linejoin="round"
                    />
                </svg>
            {:else if action.state === AsyncState.Failed}
                <!-- Cross -->
                <svg
                    viewBox="0 0 16 16"
                    width="14"
                    height="14"
                    aria-hidden="true"
                >
                    <path
                        d="M4 4l8 8M12 4l-8 8"
                        fill="none"
                        stroke="currentColor"
                        stroke-width="2"
                        stroke-linecap="round"
                    />
                </svg>
            {/if}
        </span>
    {/if}

    <!-- The outcome is a colour+glyph change, so it also needs saying aloud -->
    <span class="wg-sr-only" aria-live="polite">
        {#if action.state === AsyncState.Done}
            Done
        {:else if action.state === AsyncState.Failed}
            Failed
        {/if}
    </span>
</button>

<style>
    .wg-btn {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        gap: var(--wg-space-sm);
        height: var(--wg-control-height);
        padding: 0 var(--wg-control-padding-x);
        border-radius: var(--wg-radius-control);
        border: var(--wg-border-width) solid transparent;
        font: var(--wg-text-label-md);
        white-space: nowrap;
        cursor: pointer;
        transition:
            background var(--wg-duration-fast) var(--wg-easing),
            border-color var(--wg-duration-fast) var(--wg-easing),
            color var(--wg-duration-fast) var(--wg-easing);
    }

    .wg-btn-compact {
        height: var(--wg-control-height-compact);
        padding: 0 var(--wg-control-padding-x-compact);
        font: var(--wg-text-label-sm);
    }

    .wg-btn-block {
        width: 100%;
    }

    .wg-btn:focus-visible {
        outline: var(--wg-focus-ring);
        outline-offset: var(--wg-focus-ring-offset);
    }

    .wg-btn:disabled {
        opacity: 0.45;
        cursor: not-allowed;
    }

    /* Busy is not disabled — it keeps full contrast so the operator can still
     * read what is in flight. */
    .wg-btn-busy:disabled {
        opacity: 1;
        cursor: progress;
    }

    /* Primary */
    .wg-btn-primary {
        background: var(--wg-primary);
        color: var(--wg-on-primary);
    }
    .wg-btn-primary:hover:not(:disabled) {
        background: var(--wg-primary-container);
        color: var(--wg-on-primary-container);
    }
    .wg-btn-primary:active:not(:disabled) {
        background: var(--wg-inverse-primary);
        color: var(--wg-on-primary);
    }

    /* Secondary — the default */
    .wg-btn-secondary {
        background: var(--wg-surface-container);
        color: var(--wg-text);
        border-color: var(--wg-border-strong);
    }
    .wg-btn-secondary:hover:not(:disabled) {
        background: var(--wg-surface-container-high);
    }
    .wg-btn-secondary:active:not(:disabled) {
        background: var(--wg-surface-container-highest);
    }

    /*
     * Destructive. The solid fill is error-container, which measures 1.98:1
     * against the canvas on its own — invisible as a shape. The 1px error
     * hairline carries the boundary at 7.37:1 and satisfies 1.4.11.
     */
    .wg-btn-destructive {
        background: var(--wg-error-container);
        color: var(--wg-on-error-container);
        border-color: var(--wg-error);
    }
    .wg-btn-destructive:hover:not(:disabled) {
        background: var(--wg-error);
        color: var(--wg-on-error);
    }
    .wg-btn-destructive:active:not(:disabled) {
        background: var(--wg-error);
        color: var(--wg-on-error);
        filter: brightness(0.9);
    }

    /* Ghost — toolbar affordances that must not compete with real actions */
    .wg-btn-ghost {
        background: transparent;
        color: var(--wg-text-muted);
    }
    .wg-btn-ghost:hover:not(:disabled) {
        background: var(--wg-surface-container-high);
        color: var(--wg-text);
    }

    .wg-btn-overlay {
        display: inline-flex;
        align-items: center;
        justify-content: center;
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
