<script lang="ts">
    /**
     * Profile hub — screen 14. Migrated in place.
     *
     * ── Enumeration of the original, asserted present ────────────────────
     * The heading is the signed-in username; API tokens always; Credentials
     * only when ownCredentialManagementAllowed; Ticket requests only when
     * ticketSelfServiceEnabled. All three gates are unchanged, and a
     * destination the user cannot use is absent rather than disabled, which
     * is the same disclosure rule the admin nav follows.
     *
     * common/NavListItem is deliberately not used here. It is shared with
     * three old-UI admin screens and is not sveltestrap, so migrating it in
     * place would restyle those screens for no deletion benefit. A hub with
     * three entries does not need a shared component.
     */
    import { serverInfo } from 'gateway/lib/store'
    import { link } from 'svelte-spa-router'

    const entries = $derived(
        [
            {
                href: '/profile/api-tokens',
                title: 'API tokens',
                description: 'Manage your API tokens',
                show: true,
            },
            {
                href: '/profile/credentials',
                title: 'Credentials',
                description: 'Manage your passwords and keys',
                show: !!$serverInfo?.ownCredentialManagementAllowed,
            },
            {
                href: '/ticket-requests',
                title: 'Ticket requests',
                description: 'Request and manage self-service access tickets',
                show: !!$serverInfo?.ticketSelfServiceEnabled,
            },
        ].filter(e => e.show),
    )
</script>

<div class="head">
    {#if $serverInfo}
        <h1>{$serverInfo.username}</h1>
    {/if}
</div>

<ul class="hub">
    {#each entries as entry (entry.href)}
        <li>
            <a href={entry.href} use:link>
                <span class="hub-text">
                    <span class="hub-title">{entry.title}</span>
                    <span class="hub-description">{entry.description}</span>
                </span>
                <span class="hub-go" aria-hidden="true">&rarr;</span>
            </a>
        </li>
    {/each}
</ul>

<style>
    .head {
        margin-bottom: var(--wg-space-xl);
    }

    h1 {
        margin: 0;
        font: var(--wg-text-headline-lg);
        overflow-wrap: anywhere;
    }

    .hub {
        list-style: none;
        margin: 0;
        padding: 0;
        display: flex;
        flex-direction: column;
        gap: var(--wg-space-sm);
    }

    .hub a {
        display: flex;
        align-items: center;
        gap: var(--wg-space-md);
        padding: var(--wg-space-lg);
        background: var(--wg-surface-container);
        border: var(--wg-border-width) solid var(--wg-border);
        border-radius: var(--wg-radius-panel);
        color: var(--wg-text);
        text-decoration: none;
    }

    .hub a:hover {
        background: var(--wg-surface-container-high);
    }

    .hub a:focus-visible {
        outline: var(--wg-focus-ring);
        outline-offset: var(--wg-focus-ring-offset);
    }

    .hub-text {
        display: flex;
        flex-direction: column;
        gap: 2px;
        min-width: 0;
    }

    .hub-title {
        font: var(--wg-text-body-md);
    }

    .hub-description {
        color: var(--wg-text-muted);
        font: var(--wg-text-label-sm);
    }

    .hub-go {
        margin-left: auto;
        color: var(--wg-text-muted);
    }

    @media (max-width: 640px) {
        h1 {
            font: var(--wg-text-headline-lg-mobile);
        }
    }
</style>
