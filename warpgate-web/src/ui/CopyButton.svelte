<script lang="ts">
    /**
     * Copy-to-clipboard button.
     *
     * Replaces common/CopyButton.svelte, which was built on sveltestrap's
     * Button and svelte-fa. Two new-UI screens had imported it, which would
     * have kept sveltestrap alive past the deletion commit.
     *
     * `copy-text-to-clipboard` is kept deliberately rather than moving to
     * `navigator.clipboard.writeText`: that API only exists in a secure
     * context, and Warpgate's admin UI is reachable over plain HTTP on
     * internal addresses. The package falls back to the execCommand textarea
     * trick, which works there. Swapping it would break copying in exactly
     * the deployments this fork targets.
     *
     * Two fixes over the original:
     *   - the confirmation was an icon swap only, so a screen reader user got
     *     no signal that anything had happened. There is now a polite live
     *     region carrying it.
     *   - the 2s timer was never cleared, so a second click within the window
     *     inherited the first click's timer and the tick vanished early.
     */

    import copyTextToClipboard from 'copy-text-to-clipboard'
    import { onDestroy } from 'svelte'
    import type { ButtonSize, ButtonVariant } from './Button.svelte'
    import Button from './Button.svelte'

    interface Props {
        text: string
        /** Visible text. Omit for an icon-only button. */
        label?: string
        variant?: ButtonVariant
        size?: ButtonSize
        disabled?: boolean
        block?: boolean
        class?: string
        /** Accessible name when there is no visible label. */
        name?: string
    }

    let {
        text,
        label,
        variant = 'secondary',
        size = 'standard',
        disabled = false,
        block = false,
        class: className = '',
        name,
    }: Props = $props()

    let copied = $state(false)
    let timer: ReturnType<typeof setTimeout> | undefined

    function copy() {
        copyTextToClipboard(text)
        copied = true
        clearTimeout(timer)
        timer = setTimeout(() => {
            copied = false
        }, 2000)
    }

    onDestroy(() => clearTimeout(timer))

    const accessibleName = $derived(label ? undefined : (name ?? 'Copy'))
</script>

<Button
    {variant}
    {size}
    {disabled}
    {block}
    class={className}
    label={accessibleName}
    onclick={copy}
>
    {#if copied}
        <svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true">
            <path
                d="M3.5 8.5l3 3L12.5 5"
                fill="none"
                stroke="currentColor"
                stroke-width="2"
                stroke-linecap="round"
                stroke-linejoin="round"
            />
        </svg>
    {:else}
        <svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true">
            <rect
                x="5.75"
                y="5.75"
                width="7.5"
                height="7.5"
                rx="1.5"
                fill="none"
                stroke="currentColor"
                stroke-width="1.5"
            />
            <path
                d="M10.25 3.75a1.5 1.5 0 0 0-1.5-1.5h-5a1.5 1.5 0 0 0-1.5 1.5v5a1.5 1.5 0 0 0 1.5 1.5"
                fill="none"
                stroke="currentColor"
                stroke-width="1.5"
                stroke-linecap="round"
            />
        </svg>
    {/if}
    {#if label}
        <span>{label}</span>
    {/if}
</Button>

<!--
    Outside the button: moving the confirmation into the button's own content
    would re-announce its whole accessible name on every press.
-->
<span class="wg-visually-hidden" aria-live="polite">
    {copied ? 'Copied to clipboard' : ''}
</span>

<style>
    svg {
        flex: none;
    }

    .wg-visually-hidden {
        position: absolute;
        width: 1px;
        height: 1px;
        margin: -1px;
        padding: 0;
        overflow: hidden;
        clip-path: inset(50%);
        white-space: nowrap;
        border: 0;
    }
</style>
