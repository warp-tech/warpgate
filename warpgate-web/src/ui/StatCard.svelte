<script lang="ts">
    /**
     * A labelled figure: caption, one large number, an optional note.
     *
     * Built once for Tickets (screen 8) and Overview (screen 11) rather than
     * twice — both mockups use the same object and the fork check would have
     * caught the second one anyway.
     *
     * `tone` reuses the shared Tone vocabulary rather than defining a
     * parallel one, so a warning figure is the same amber as a warning
     * Callout, a warning toast and StatusMarker's `pending`. It colours the
     * figure only: the caption and note stay at their normal ink, so a
     * warning card does not become a wall of orange and the colour is never
     * the only thing carrying the meaning — callers pass a `note` that says
     * what the state is in words.
     *
     * Rendered as a <figure>, with the caption as its <figcaption>, so the
     * number is announced with the thing it counts rather than as a loose
     * digit. The caption comes first in the DOM for that reason, and is
     * re-ordered visually with flex.
     */
    import type { Snippet } from 'svelte'
    import { TONES, type Tone } from './tones'

    interface Props {
        label: string
        value: string | number
        /** Short words after the figure — "Verified live", "of 64 provisioned". */
        note?: string
        tone?: Tone | 'neutral'
        class?: string
        /** Trailing element: a badge, a sparkline, a status marker. */
        detail?: Snippet
    }

    let {
        label,
        value,
        note,
        tone = 'neutral',
        class: className = '',
        detail,
    }: Props = $props()
</script>

<figure
    class="wg-stat {className}"
    style:--wg-stat-ink={tone === 'neutral'
        ? 'var(--wg-text)'
        : `var(${TONES[tone].token})`}
>
    <figcaption>{label}</figcaption>
    <div class="wg-stat-row">
        <span class="wg-stat-value">{value}</span>
        {#if note}
            <span class="wg-stat-note">{note}</span>
        {/if}
        {#if detail}
            <span class="wg-stat-detail">{@render detail()}</span>
        {/if}
    </div>
</figure>

<style>
    .wg-stat {
        display: flex;
        flex-direction: column;
        gap: var(--wg-space-sm);
        margin: 0;
        padding: var(--wg-space-lg);
        background: var(--wg-surface-container);
        /* Decorative panel edge, not a control boundary — divider tier. */
        border: var(--wg-border-width) solid var(--wg-border);
        border-radius: var(--wg-radius-panel);
        min-width: 0;
    }

    figcaption {
        font: var(--wg-text-label-sm);
        letter-spacing: 0.06em;
        text-transform: uppercase;
        color: var(--wg-text-muted);
    }

    .wg-stat-row {
        display: flex;
        align-items: baseline;
        flex-wrap: wrap;
        gap: var(--wg-space-sm);
        min-width: 0;
    }

    .wg-stat-value {
        font: var(--wg-text-headline-lg);
        font-variant-numeric: tabular-nums;
        color: var(--wg-stat-ink);
        line-height: 1;
    }

    .wg-stat-note {
        font: var(--wg-text-body-md);
        color: var(--wg-text-muted);
        min-width: 0;
    }

    .wg-stat-detail {
        display: inline-flex;
        align-items: center;
        margin-left: auto;
    }
</style>
