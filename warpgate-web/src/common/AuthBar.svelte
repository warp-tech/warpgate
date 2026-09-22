<script lang="ts">
    /**
     * Signed-in identity, account destinations and sign-out, in both shells.
     *
     * Behaviour preserved: every destination the username used to reach, the
     * "(ticket auth)" note, plain logout, and the two-way choice between
     * logging out of Warpgate and single-logout at the identity provider when
     * the session came in via SSO with SLO.
     *
     * ── Why this is a menu and not a link ────────────────────────────────
     * The username used to be a bare link to /profile. Nothing said it was
     * interactive, nothing said where it went, and the page it landed on has
     * no sidebar and no breadcrumb — so an accidental click read as leaving
     * the application, with the browser's back button as the only way home.
     *
     * A menu answers all three at once: the chevron announces the trigger,
     * the items name their destinations before you commit, and Profile, API
     * tokens and Credentials are each reachable directly, so the profile page
     * stops being a hub you have to pass through to get anywhere.
     *
     * The hrefs are absolute rather than hash-relative because this component
     * renders in BOTH shells, and a bare `#/profile` from the admin shell
     * would be resolved by the admin router, which has no such route.
     */
    import { navigateToExternalUrl } from 'common/helpers'
    import { api } from 'gateway/lib/api'
    import { reloadServerInfo, serverInfo } from 'gateway/lib/store'
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

    const PORTAL = '/@warpgate/#'

    const accountGroups = $derived([
        {
            label: $serverInfo?.username,
            items: [
                { id: 'profile', label: 'Profile', href: `${PORTAL}/profile` },
                {
                    id: 'api-tokens',
                    label: 'API tokens',
                    href: `${PORTAL}/profile/api-tokens`,
                },
                {
                    id: 'credentials',
                    label: 'Credentials',
                    href: `${PORTAL}/profile/credentials`,
                },
            ],
        },
        {
            // Both sign-out choices when the session came via SSO with single
            // logout; otherwise the one that exists. Logging out everywhere
            // ends sessions beyond Warpgate, so it is marked destructive.
            items: $serverInfo?.authorizedViaSsoWithSingleLogout
                ? [
                      {
                          id: 'logout',
                          label: 'Log out of Warpgate',
                          onselect: () => void logout(),
                      },
                      {
                          id: 'slo',
                          label: 'Log out everywhere',
                          danger: true,
                          onselect: () => void singleLogout(),
                      },
                  ]
                : [
                      {
                          id: 'logout',
                          label: 'Log out',
                          onselect: () => void logout(),
                      },
                  ],
        },
    ])
</script>

{#if $serverInfo?.username}
    <div class="authbar">
        {#if $serverInfo.authorizedViaTicket}
            <span class="note">(ticket auth)</span>
        {/if}

        <Menu
            groups={accountGroups}
            label="Account menu"
            triggerLabel={$serverInfo.username}
            triggerIcon="chevron"
            align="end"
        />
    </div>
{/if}

<style>
    .authbar {
        display: flex;
        align-items: center;
        gap: var(--wg-space-sm);
        min-width: 0;
    }

    .note {
        color: var(--wg-text-muted);
        font: var(--wg-text-label-sm);
    }
</style>
