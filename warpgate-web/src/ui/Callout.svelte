<script lang="ts">
    /**
     * Inline status message. Replaces sveltestrap's Alert — 70 call sites
     * across 43 files, and the most-used Bootstrap component in the codebase.
     *
     * Distinct from its neighbours, and the distinction is what stops them
     * blurring:
     *   Callout      in-flow, part of the page, persists while the condition does
     *   Toast        floating, transient, global, about an action just taken
     *   StatusMarker a row's state, not a message about it
     *
     * Colour lives on the left edge and the marker; the fill stays subdued,
     * per DESIGN.md's rule that accents sit on border and glyph so a page of
     * these does not become a colour chart.
     *
     * Live-region policy matches Toast: polite by default, assertive only for
     * `danger`, because a page rendering three info callouts should not
     * interrupt a screen reader three times. `assertive` can be forced —
     * KeyChecker's changed-host-key warning appears on navigation rather than
     * after an action, but it is the SSH MITM warning and interrupting is the
     * entire point of it.
     */
    import type { Snippet } from 'svelte'
    import { TONES, type Tone } from './tones'
    import './markers.css'

    interface Props {
        tone?: Tone
        /** Bold first line. Omit for a single-line message. */
        title?: string
        /**
         * Forces the assertive live region on a non-danger tone, or keeps it
         * on a danger tone that is purely decorative. Defaults to
         * assertive for danger, polite otherwise.
         */
        assertive?: boolean
        class?: string
        children?: Snippet
        /** Buttons sitting beside the message. */
        actions?: Snippet
    }

    let {
        tone = 'info',
        title,
        assertive,
        class: className = '',
        children,
        actions,
    }: Props = $props()

    const spec = $derived(TONES[tone])
    const isAssertive = $derived(assertive ?? tone === 'danger')
</script>

<div
    class="wg-callout wg-callout-{tone} {className}"
    role={isAssertive ? 'alert' : 'status'}
    aria-live={isAssertive ? 'assertive' : 'polite'}
>
    <span
        class="wg-marker wg-marker-{spec.shape} wg-callout-marker"
        style="--marker: var({spec.token})"
        aria-hidden="true"
    ></span>

    <div class="wg-callout-body">
        {#if title}
            <p class="wg-callout-title">{title}</p>
        {/if}
        {#if children}
            <div class="wg-callout-content">
                {@render children()}
            </div>
        {/if}
    </div>

    {#if actions}
        <div class="wg-callout-actions">
            {@render actions()}
        </div>
    {/if}
</div>

<style>
    .wg-callout {
        display: flex;
        align-items: flex-start;
        gap: var(--wg-space-sm);
        padding: var(--wg-space-md);
        background: var(--wg-surface-container);
        border: var(--wg-border-width) solid var(--wg-border);
        border-left: 2px solid var(--tone, var(--wg-border-strong));
        border-radius: var(--wg-radius-panel);
        color: var(--wg-text);
        font: var(--wg-text-body-md);
    }

    .wg-callout-info {
        --tone: var(--wg-primary);
    }
    .wg-callout-success {
        --tone: var(--wg-tertiary);
    }
    .wg-callout-warning {
        --tone: var(--wg-secondary);
    }
    .wg-callout-danger {
        --tone: var(--wg-error);
    }

    /* Optically centred against the first line of text rather than the box */
    .wg-callout-marker {
        margin-top: 0.4rem;
    }

    .wg-callout-body {
        flex: 1 1 auto;
        min-width: 0;
    }

    .wg-callout-title {
        margin: 0;
        font: var(--wg-text-label-md);
    }

    .wg-callout-content {
        margin-top: var(--wg-space-xs);
        color: var(--wg-text-muted);
        overflow-wrap: anywhere;
    }

    /* A title with no body reads as the message itself, not as a heading */
    .wg-callout-body:has(.wg-callout-title:only-child) .wg-callout-title {
        font: var(--wg-text-body-md);
    }

    .wg-callout-actions {
        display: flex;
        flex-direction: column;
        align-items: stretch;
        gap: var(--wg-space-sm);
        flex: none;
    }

    @media (max-width: 560px) {
        .wg-callout {
            flex-wrap: wrap;
        }

        .wg-callout-actions {
            flex-direction: row;
            width: 100%;
        }
    }
</style>
