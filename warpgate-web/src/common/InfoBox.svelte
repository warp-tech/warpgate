<script lang="ts">
    /**
     * An inline hint line — screen 13, chrome only.
     *
     * Deliberately NOT folded into ui/Callout. A Callout is a bordered block
     * that claims a paragraph of attention; this is one muted line beside a
     * small glyph, used for asides inside a form. They read as different
     * weights and collapsing them would make every aside shout.
     *
     * The tones do share Callout's vocabulary: `warning` is the same amber
     * token and the same diamond geometry, so a warning hint and a warning
     * callout are recognisably the same kind of thing at different volumes.
     */
    import type { Snippet } from 'svelte'
    import 'ui/markers.css'

    interface Props {
        class?: string
        children: Snippet
        variant?: 'info' | 'warning'
    }

    let { children, class: className = '', variant = 'info' }: Props = $props()
</script>

<div class="info-box info-box-{variant} {className}">
    <span
        class="wg-marker wg-marker-{variant === 'warning'
            ? 'diamond'
            : 'dot'}"
        style:--marker={variant === 'warning'
            ? 'var(--wg-secondary)'
            : 'var(--wg-primary)'}
        aria-hidden="true"
    ></span>
    <small>{@render children()}</small>
</div>

<style>
    .info-box {
        display: flex;
        gap: var(--wg-space-sm);
        align-items: baseline;
        margin: var(--wg-space-md) 0 var(--wg-space-lg);
        line-height: 1.3;
        color: var(--wg-text-muted);
    }

    .info-box-warning {
        color: var(--wg-secondary);
    }

    .info-box small {
        font: var(--wg-text-label-sm);
    }

    .wg-marker {
        flex: none;
        transform: translateY(-1px);
    }
</style>
