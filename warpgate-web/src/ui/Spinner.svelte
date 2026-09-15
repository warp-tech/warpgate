<script lang="ts">
    interface Props {
        size?: number
        /** Omit for a decorative spinner sitting inside a labelled control. */
        label?: string
    }

    let { size = 14, label }: Props = $props()
</script>

<!--
  Two branches rather than one element with conditional ARIA. A labelled
  spinner is a live region; an unlabelled one is decoration sitting inside a
  control that already announces itself, and putting aria-label on a roleless
  span is meaningless in both cases.
-->
{#if label}
    <span
        class="wg-spinner"
        style="--size: {size}px"
        role="status"
        aria-label={label}
    ></span>
{:else}
    <span class="wg-spinner" style="--size: {size}px" aria-hidden="true"></span>
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
