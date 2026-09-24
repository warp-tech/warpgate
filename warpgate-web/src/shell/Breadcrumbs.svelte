<script lang="ts" module>
    export interface Crumb {
        label: string
        /** Omitted on the last crumb, which is the current page. */
        href?: string
        mono?: boolean
    }
</script>

<script lang="ts">
    /**
     * The last crumb is the current page and is never a link — it is marked
     * `aria-current="page"` instead. A link to where you already are is a
     * keyboard stop that does nothing.
     *
     * Separators are CSS pseudo-elements rather than text nodes, so a screen
     * reader reads "Targets, prod-bastion-01" and not "Targets slash
     * prod-bastion-01".
     */
    interface Props {
        crumbs: Crumb[]
    }

    let { crumbs }: Props = $props()
</script>

{#if crumbs.length}
    <nav aria-label="Breadcrumb" class="wg-crumbs">
        <ol>
            {#each crumbs as crumb, i (crumb.label + i)}
                {@const last = i === crumbs.length - 1}
                <li>
                    {#if last || !crumb.href}
                        <span
                            class="wg-crumb-current"
                            class:wg-crumb-mono={crumb.mono}
                            aria-current={last ? 'page' : undefined}
                        >
                            {crumb.label}
                        </span>
                    {:else}
                        <a href={crumb.href} class:wg-crumb-mono={crumb.mono}>
                            {crumb.label}
                        </a>
                    {/if}
                </li>
            {/each}
        </ol>
    </nav>
{/if}

<style>
    .wg-crumbs {
        min-width: 0;
    }

    ol {
        display: flex;
        align-items: center;
        flex-wrap: wrap;
        list-style: none;
        margin: 0;
        padding: 0;
        font: var(--wg-text-label-md);
    }

    li {
        display: flex;
        align-items: center;
        min-width: 0;
    }

    li + li::before {
        content: "/";
        margin: 0 var(--wg-space-sm);
        color: var(--wg-text-subtle);
    }

    a {
        color: var(--wg-text-muted);
        text-decoration: none;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
    }

    a:hover {
        color: var(--wg-text);
        text-decoration: underline;
    }

    a:focus-visible {
        outline: var(--wg-focus-ring);
        outline-offset: var(--wg-focus-ring-offset);
        border-radius: var(--wg-radius-sm);
    }

    .wg-crumb-current {
        color: var(--wg-text);
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
    }

    .wg-crumb-mono {
        font-family: var(--wg-font-mono);
    }
</style>
