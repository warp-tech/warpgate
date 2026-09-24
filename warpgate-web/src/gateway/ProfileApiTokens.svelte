<script lang="ts">
    /**
     * API tokens page — screen 14. Migrated in place.
     *
     * Behaviour preserved: the manager, the four external links to the user
     * and admin API playgrounds and schemas (each still target="_blank"), and
     * the X-Warpgate-Token header note.
     *
     * rel="noreferrer" added to the external links. They are same-origin so
     * there is no window.opener risk, but the Referer they leak carries the
     * portal URL, and these open the API playground — a page where a reader
     * does not need to be told where the operator came from.
     */
    import InfoBox from 'common/InfoBox.svelte'
    import ApiTokenManager from './ApiTokenManager.svelte'

    const API_LINKS = [
        {
            heading: 'User API',
            links: [
                { label: 'Playground', href: '/@warpgate/api/playground' },
                { label: 'Schema', href: '/@warpgate/api/openapi.json' },
            ],
        },
        {
            heading: 'Admin API',
            links: [
                {
                    label: 'Playground',
                    href: '/@warpgate/admin/api/playground',
                },
                {
                    label: 'Schema',
                    href: '/@warpgate/admin/api/openapi.json',
                },
            ],
        },
    ]
</script>

<ApiTokenManager />

<div class="api-links">
    {#each API_LINKS as section (section.heading)}
        <div>
            <h2>{section.heading}</h2>
            <ul>
                {#each section.links as l (l.href)}
                    <li>
                        <a href={l.href} target="_blank" rel="noreferrer">
                            {l.label}
                        </a>
                    </li>
                {/each}
            </ul>
        </div>
    {/each}
</div>

<InfoBox> Pass the token in the <code>X-Warpgate-Token</code> header </InfoBox>

<style>
    .api-links {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(12rem, 1fr));
        gap: var(--wg-space-xl);
        margin-top: var(--wg-space-3xl);
    }

    h2 {
        margin: 0 0 var(--wg-space-sm);
        font: var(--wg-text-label-md);
        color: var(--wg-text-muted);
    }

    ul {
        list-style: none;
        margin: 0;
        padding: 0;
        display: flex;
        flex-direction: column;
        gap: var(--wg-space-xs);
    }

    a {
        color: var(--wg-primary);
        font: var(--wg-text-body-md);
    }

    a:focus-visible {
        outline: var(--wg-focus-ring);
        outline-offset: var(--wg-focus-ring-offset);
    }

    code {
        font: var(--wg-text-code-sm);
        color: var(--wg-text);
    }
</style>
