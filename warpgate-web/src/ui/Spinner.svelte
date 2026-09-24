<script lang="ts">
    interface Props {
        size?: number
        /** Omit for a decorative spinner sitting inside a labelled control. */
        label?: string
        /**
         * ms to wait before appearing. Replaces common/DelayedSpinner.svelte,
         * which was a separate sveltestrap component wrapping exactly this.
         * A spinner that flashes for 80ms reads as a glitch, so a slow load
         * gets one and a fast load shows nothing at all.
         */
        delay?: number
    }

    let { size = 14, label, delay = 0 }: Props = $props()

    // `visible` is derived rather than seeded state so the undelayed case —
    // every other call site — still paints on the first frame instead of one
    // microtask later, which would shift layout inside buttons.
    let elapsed = $state(false)
    const visible = $derived(delay === 0 || elapsed)

    $effect(() => {
        if (delay === 0) {
            return
        }
        elapsed = false
        const t = setTimeout(() => {
            elapsed = true
        }, delay)
        return () => clearTimeout(t)
    })
</script>

<!--
  Two branches rather than one element with conditional ARIA. A labelled
  spinner is a live region; an unlabelled one is decoration sitting inside a
  control that already announces itself, and putting aria-label on a roleless
  span is meaningless in both cases.
-->
{#if visible}
    {#if label}
        <span
            class="wg-spinner"
            style="--size: {size}px"
            role="status"
            aria-label={label}
        ></span>
    {:else}
        <span
            class="wg-spinner"
            style="--size: {size}px"
            aria-hidden="true"
        ></span>
    {/if}
{/if}

<style>
    .wg-spinner {
        display: inline-block;
        width: var(--size);
        height: var(--size);
        border: 2px solid currentColor;
        border-right-color: transparent;
        border-radius: var(--wg-radius-full);
        animation: wg-spin 0.7s linear infinite;
    }

    /*
     * Reduced motion gets a static three-quarter ring rather than nothing —
     * the control still needs to read as "working", just without the spin.
     */
    @media (prefers-reduced-motion: reduce) {
        .wg-spinner {
            animation: none;
            opacity: 0.6;
        }
    }

    @keyframes wg-spin {
        to {
            transform: rotate(360deg);
        }
    }
</style>
