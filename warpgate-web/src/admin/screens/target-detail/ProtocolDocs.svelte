<script lang="ts">
    /**
     * Per-protocol requirements and supported features, rendered from the
     * markdown in config/targets/protocolInfo.ts — which stays where it is,
     * since it is content rather than chrome.
     *
     * Built on native <details> rather than CollapsibleBlock: the disclosure
     * behaviour, keyboard operability and expanded state all come from the
     * platform. Open state persists under a namespaced key, for the same
     * reason the theme does — HTTP targets proxied at the portal root share
     * one localStorage with everything the portal proxies.
     */
    import type { TargetKind } from 'gateway/lib/api'
    import snarkdown from 'snarkdown'
    import { protocolInfo } from '../../config/targets/protocolInfo'

    interface Props {
        kind: TargetKind
    }

    const { kind }: Props = $props()

    const STORAGE_KEY = 'warpgateTargetProtocolDocsOpen'

    const markdown = $derived(protocolInfo[kind])
    const html = $derived(markdown ? snarkdown(markdown) : undefined)

    let open = $state(true)

    $effect(() => {
        try {
            const saved = localStorage.getItem(STORAGE_KEY)
            if (saved !== null) {
                open = saved === '1'
            }
        } catch {
            // Storage can throw in a private window; the default stands.
        }
    })

    function onToggle(event: Event) {
        open = (event.currentTarget as HTMLDetailsElement).open
        try {
            localStorage.setItem(STORAGE_KEY, open ? '1' : '0')
        } catch {
            // Persistence is a convenience.
        }
    }
</script>

{#if html}
    <details class="docs" {open} ontoggle={onToggle}>
        <summary>Protocol requirements and supported features</summary>
        <!-- Trusted content: protocolInfo.ts is a source file in this repo,
             not anything a user or API can influence. -->
        <div class="docs-body">{@html html}</div>
    </details>
{/if}

<style>
    .docs {
        border: var(--wg-border-width) solid var(--wg-border);
        border-radius: var(--wg-radius-panel);
        background: var(--wg-surface-container);
    }

    summary {
        padding: var(--wg-space-sm) var(--wg-space-md);
        font: var(--wg-text-label-md);
        color: var(--wg-text);
        cursor: pointer;
    }

    summary:focus-visible {
        outline: var(--wg-focus-ring);
        outline-offset: calc(-1 * var(--wg-focus-ring-width));
        border-radius: var(--wg-radius-panel);
    }

    .docs-body {
        padding: 0 var(--wg-space-md) var(--wg-space-md);
        font: var(--wg-text-label-sm);
        color: var(--wg-text-muted);
    }

    .docs-body :global(h2) {
        margin: var(--wg-space-md) 0 var(--wg-space-xs);
        font: var(--wg-text-label-md);
        color: var(--wg-text);
    }

    .docs-body :global(p) {
        margin: 0 0 var(--wg-space-sm);
    }

    .docs-body :global(ul) {
        margin: 0 0 var(--wg-space-sm);
        padding-left: var(--wg-space-lg);
    }

    .docs-body :global(code) {
        font-family: var(--wg-font-mono);
        color: var(--wg-text);
    }

    .docs-body :global(a) {
        color: var(--wg-primary);
    }
</style>
