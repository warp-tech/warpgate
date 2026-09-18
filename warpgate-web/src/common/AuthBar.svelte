<script lang="ts">
    /**
     * Signed-in identity and sign-out, in both app shells.
     *
     * Behaviour preserved: the username links to the portal profile, the
     * "(ticket auth)" note, plain logout, and the two-way choice between
     * logging out of Warpgate and single-logout at the identity provider when
     * the session came in via SSO with SLO.
     *
     * The dropdown becomes ui/Menu, so the two sign-out choices are real menu
     * items with keyboard support. The single-button case keeps its accessible
     * name, which the icon-only sveltestrap Button carried only as a `title`.
     */
    import { navigateToExternalUrl } from 'common/helpers'
    import { api } from 'gateway/lib/api'
    import { reloadServerInfo, serverInfo } from 'gateway/lib/store'
    import Button from 'ui/Button.svelte'
    import Menu from 'ui/Menu.svelte'

    async function logout() {
        await api.logout()
        await reloadServerInfo()
        location.href = '/@warpgate'
    }

    async function singleLogout() {
        const response = await api.initiateSsoLogout()
        navigateToExternalUrl(response.url)
    }

    const logoutGroups = [
        {
            items: [
                {
                    id: 'logout',
                    label: 'Log out of Warpgate',
                    onselect: () => void logout(),
                },
                {
                    id: 'slo',
                    label: 'Log out everywhere',
                    onselect: () => void singleLogout(),
                },
            ],
        },
    ]
</script>

{#if $serverInfo?.username}
    <div class="authbar">
        <a class="who" href="/@warpgate/#/profile">{$serverInfo.username}</a>
        {#if $serverInfo.authorizedViaTicket}
            <span class="note">(ticket auth)</span>
        {/if}

        {#if $serverInfo?.authorizedViaSsoWithSingleLogout}
            <Menu groups={logoutGroups} label="Log out options" align="end" />
        {:else}
            <Button
                variant="ghost"
                size="compact"
                label="Log out"
                click={logout}
            >
                <svg
                    viewBox="0 0 16 16"
                    width="14"
                    height="14"
                    aria-hidden="true"
                >
                    <path
                        d="M6 14H3.5A1.5 1.5 0 0 1 2 12.5v-9A1.5 1.5 0 0 1 3.5 2H6"
                        fill="none"
                        stroke="currentColor"
                        stroke-width="1.5"
                        stroke-linecap="round"
                    />
                    <path
                        d="M10.5 11L13.5 8l-3-3M13 8H6"
                        fill="none"
                        stroke="currentColor"
                        stroke-width="1.5"
                        stroke-linecap="round"
                        stroke-linejoin="round"
                    />
                </svg>
            </Button>
        {/if}
    </div>
{/if}

<style>
    .authbar {
        display: flex;
        align-items: center;
        gap: var(--wg-space-sm);
        min-width: 0;
    }

    .who {
        color: var(--wg-text);
        font: var(--wg-text-body-md);
        text-decoration: none;
        overflow-wrap: anywhere;
    }

    .who:hover {
        text-decoration: underline;
    }

    .who:focus-visible {
        outline: var(--wg-focus-ring);
        outline-offset: var(--wg-focus-ring-offset);
    }

    .note {
        color: var(--wg-text-muted);
        font: var(--wg-text-label-sm);
    }
</style>
