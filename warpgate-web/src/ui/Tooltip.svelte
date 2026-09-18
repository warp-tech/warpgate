<script lang="ts">
    /**
     * Replaces sveltestrap's Tooltip (11 call sites today).
     *
     * A tooltip is supplementary by definition, so it never carries the only
     * copy of anything: it describes (`aria-describedby`), it does not name.
     * If a control has no visible text, give it a `label`, not a tooltip.
     *
     * Follows the APG tooltip pattern: shows on hover AND on keyboard focus,
     * dismissable with Escape while it is open, and the trigger keeps its own
     * accessible name.
     */
    import type { Snippet } from 'svelte'

    interface Props {
        text: string
        placement?: 'top' | 'bottom' | 'left' | 'right'
        /** ms before showing on hover; focus shows immediately. */
        delay?: number
        class?: string
        children: Snippet
    }

    let {
        text,
        placement = 'top',
        delay = 300,
        class: className = '',
        children,
    }: Props = $props()

    const id = `wg-tip-${Math.random().toString(36).slice(2, 9)}`
    let open = $state(false)
    let timer: ReturnType<typeof setTimeout> | undefined

    function show(immediate = false) {
        clearTimeout(timer)
        if (immediate) {
            open = true
            return
        }
        timer = setTimeout(() => {
            open = true
        }, delay)
    }

    function hide() {
        clearTimeout(timer)
        open = false
    }

    function onkeydown(event: KeyboardEvent) {
        if (event.key === 'Escape' && open) {
            // Stops the Escape also closing a dialog the trigger sits inside
            event.stopPropagation()
            hide()
        }
    }
</script>

<!--
  Targeted suppression, not a blanket one.

  The wrapper is a positioning context, not a widget — the interactive thing
  is whatever the caller passes as `children`, usually a button that brings
  its own role and accessible name. The handlers live here because hover and
  focus have to be observed around arbitrary content, and ARIA has no role for
  "element that reveals a tooltip about its child". Giving this span a role
  would invent a widget that is not there and would be worse for a screen
  reader than the lint it silences.
-->
<!-- svelte-ignore a11y_no_static_element_interactions -->

<span
    class="wg-tip-wrap {className}"
    onmouseenter={() => show()}
    onmouseleave={hide}
    onfocusin={() => show(true)}
    onfocusout={hide}
    {onkeydown}
>
    <span aria-describedby={open ? id : undefined} class="wg-tip-trigger">
        {@render children()}
    </span>

    {#if open}
        <span class="wg-tip wg-tip-{placement}" role="tooltip" {id}>
            {text}
        </span>
    {/if}
</span>

<style>
    .wg-tip-wrap {
        position: relative;
        display: inline-flex;
    }

    .wg-tip-trigger {
        display: inline-flex;
    }

    .wg-tip {
        position: absolute;
        z-index: 1200;
        max-width: 18rem;
        width: max-content;
        padding: var(--wg-space-xs) var(--wg-space-sm);
        background: var(--wg-inverse-surface);
        color: var(--wg-inverse-on-surface);
        border-radius: var(--wg-radius-badge);
        font: var(--wg-text-label-sm);
        /* Pointer-transparent so it cannot eat a click aimed at the trigger */
        pointer-events: none;
        animation: wg-tip-in var(--wg-duration-instant) var(--wg-easing);
    }

    .wg-tip-top {
        bottom: calc(100% + var(--wg-space-xs));
        left: 50%;
        transform: translateX(-50%);
    }

    .wg-tip-bottom {
        top: calc(100% + var(--wg-space-xs));
        left: 50%;
        transform: translateX(-50%);
    }

    .wg-tip-left {
        right: calc(100% + var(--wg-space-xs));
        top: 50%;
        transform: translateY(-50%);
    }

    .wg-tip-right {
        left: calc(100% + var(--wg-space-xs));
        top: 50%;
        transform: translateY(-50%);
    }

    @keyframes wg-tip-in {
        from {
            opacity: 0;
        }
    }

    @media (prefers-reduced-motion: reduce) {
        .wg-tip {
            animation: none;
        }
    }
</style>
