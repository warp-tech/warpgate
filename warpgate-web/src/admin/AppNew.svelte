<script lang="ts">
    import AuthBar from 'common/AuthBar.svelte'
    /**
     * Admin shell.
     */
    import Brand from 'common/Brand.svelte'
    import Loadable from 'common/Loadable.svelte'
    import RequestsButton from 'common/RequestsButton.svelte'
    import ThemeSwitcher from 'common/ThemeSwitcher.svelte'
    import { reloadServerInfo, serverInfo } from 'gateway/lib/store'
    import AppShell from 'shell/AppShell.svelte'
    import { get } from 'svelte/store'
    import Router, { router, type WrappedComponent } from 'svelte-spa-router'
    import { wrap } from 'svelte-spa-router/wrap'
    import AnalyticsConsentModal from './AnalyticsConsentModal.svelte'
    import { crumbsFor } from './crumbs'
    import { ADMIN_PERMISSIONS, adminPermissions } from './lib/store'

    let showAnalyticsModal = $state(false)
    $effect(() => {
        if (
            ($serverInfo?.shouldPromptAnalytics ?? false) &&
            $serverInfo?.adminPermissions?.configEdit
        ) {
            setTimeout(() => {
                showAnalyticsModal = true
            }, 1000)
        }
    })

    // Identical to App.svelte's init — the auth gate is shell-independent and
    // is not something this redesign changes.
    async function init() {
        await reloadServerInfo()
        const permissions = get(serverInfo)?.adminPermissions
        if (
            !get(serverInfo)?.username ||
            !permissions ||
            !ADMIN_PERMISSIONS.some(p => permissions[p.key])
        ) {
            const next = location.pathname + location.hash
            location.assign(
                `/@warpgate#/login?next=${encodeURIComponent(next)}`,
            )
            await new Promise(() => undefined)
        }
        if (get(serverInfo)?.needsMfaSetup) {
            location.assign('/@warpgate#/mfa-setup')
            await new Promise(() => undefined)
        }
    }

    const initPromise = init()

    /**
     * Every route is listed explicitly rather than delegating /config/* to a
     * sub-router.
     *
     * ORDER IS SIGNIFICANT. svelte-spa-router keeps these in declaration order
     * and returns the FIRST pattern that matches, so a `:param` route declared
     * above a literal sibling swallows it. `/config/targets/:id` sitting above
     * `/config/targets/create` made "create" an id, and the detail screen then
     * asked the API for a target whose UUID was the word "create" — which is
     * what `failed to parse "string_uuid": invalid character: found r at 1`
     * was. A 500 from the server for a button that should have opened a form.
     *
     * So: routes are grouped by family, and within a family every literal path
     * comes before any `:param` path. Keeping a family together is the point —
     * the bug arrived when `/config/targets/:id` was moved into a "migrated"
     * block at the top and its `create` siblings stayed behind.
     */
    const routes: Record<string, WrappedComponent> = {
        '/': wrap({
            asyncComponent: () => import('./screens/Overview.svelte'),
        }),

        // ---- sessions ----
        '/status/sessions': wrap({
            asyncComponent: () => import('./screens/Sessions.svelte'),
        }),
        '/status/sessions/:id': wrap({
            asyncComponent: () => import('./screens/Session.svelte'),
        }),
        '/status/recordings/:id': wrap({
            asyncComponent: () => import('./status/Recording.svelte'),
        }),

        // ---- status ----
        '/status/requests': wrap({
            asyncComponent: () => import('./status/Requests.svelte'),
        }),
        '/status/login-protection': wrap({
            asyncComponent: () => import('./screens/LoginProtection.svelte'),
        }),
        '/status/network': wrap({
            asyncComponent: () => import('./status/NetworkStatus.svelte'),
        }),

        // ---- audit log ----
        '/log': wrap({
            asyncComponent: () => import('./screens/Log.svelte'),
        }),
        '/log/user/:id': wrap({
            asyncComponent: () => import('./screens/Log.svelte'),
            props: { filterKind: 'user' },
        }),
        '/log/access-role/:id': wrap({
            asyncComponent: () => import('./screens/Log.svelte'),
            props: { filterKind: 'access-role' },
        }),
        '/log/admin-role/:id': wrap({
            asyncComponent: () => import('./screens/Log.svelte'),
            props: { filterKind: 'admin-role' },
        }),

        // ---- targets ----
        '/config/targets': wrap({
            asyncComponent: () => import('./screens/Targets.svelte'),
        }),
        '/config/targets/create': wrap({
            asyncComponent: () =>
                import('./config/targets/ChooseTargetKind.svelte'),
        }),
        '/config/targets/create/:kind': wrap({
            asyncComponent: () =>
                import('./config/targets/CreateTarget.svelte'),
        }),
        '/config/targets/:id': wrap({
            asyncComponent: () =>
                import('./screens/target-detail/Target.svelte'),
        }),

        // ---- target groups ----
        '/config/target-groups': wrap({
            asyncComponent: () =>
                import('./config/target-groups/TargetGroups.svelte'),
        }),
        '/config/target-groups/create': wrap({
            asyncComponent: () =>
                import('./config/target-groups/CreateTargetGroup.svelte'),
        }),
        '/config/target-groups/:id': wrap({
            asyncComponent: () =>
                import('./config/target-groups/TargetGroup.svelte'),
        }),

        // ---- users ----
        '/config/users': wrap({
            asyncComponent: () => import('./screens/Users.svelte'),
        }),
        '/config/users/create': wrap({
            asyncComponent: () => import('./config/CreateUser.svelte'),
        }),
        '/config/users/:id': wrap({
            asyncComponent: () => import('./screens/user-detail/User.svelte'),
        }),

        // ---- access roles ----
        '/config/access-roles': wrap({
            asyncComponent: () => import('./screens/Roles.svelte'),
        }),
        '/config/access-roles/create': wrap({
            asyncComponent: () => import('./config/CreateRole.svelte'),
        }),
        '/config/access-roles/:id': wrap({
            asyncComponent: () => import('./config/AccessRole.svelte'),
        }),

        // ---- admin roles ----
        '/config/admin-roles': wrap({
            asyncComponent: () => import('./config/AdminRoles.svelte'),
        }),
        '/config/admin-roles/create': wrap({
            asyncComponent: () => import('./config/CreateAdminRole.svelte'),
        }),
        '/config/admin-roles/:id': wrap({
            asyncComponent: () => import('./config/AdminRole.svelte'),
        }),

        // ---- tickets ----
        '/config/tickets': wrap({
            asyncComponent: () => import('./screens/tickets/Tickets.svelte'),
        }),
        '/config/tickets/create': wrap({
            asyncComponent: () =>
                import('./screens/tickets/CreateTicket.svelte'),
        }),

        // ---- LDAP ----
        '/config/ldap-servers': wrap({
            asyncComponent: () => import('./config/ldap/LdapServers.svelte'),
        }),
        '/config/ldap-servers/create': wrap({
            asyncComponent: () =>
                import('./config/ldap/CreateLdapServer.svelte'),
        }),
        '/config/ldap-servers/:id/users': wrap({
            asyncComponent: () =>
                import('./config/ldap/LdapUserBrowser.svelte'),
        }),
        '/config/ldap-servers/:id': wrap({
            asyncComponent: () => import('./config/ldap/LdapServer.svelte'),
        }),

        // ---- global config ----
        '/config/ssh': wrap({
            asyncComponent: () => import('./config/SSHKeys.svelte'),
        }),
        '/config/policies': wrap({
            asyncComponent: () => import('./config/Policies.svelte'),
        }),
        '/config/parameters': wrap({
            asyncComponent: () => import('./config/Parameters.svelte'),
        }),
    }

    const path = $derived(router.location)
    const crumbs = $derived(crumbsFor(path))
</script>

<Loadable promise={initPromise}>
    <AppShell permissions={$adminPermissions} {path} {crumbs}>
        {#snippet brand()}
            <a
                href="/@warpgate"
                class="wg-brand-link"
                aria-label="Warpgate home"
            >
                <Brand />
            </a>
        {/snippet}

        {#snippet trailing()}
            <RequestsButton collapsed />
            <ThemeSwitcher />
            <AuthBar />
        {/snippet}

        <Router {routes} />
    </AppShell>
</Loadable>

{#if showAnalyticsModal}
    <AnalyticsConsentModal bind:isOpen={showAnalyticsModal} />
{/if}

<style>
    .wg-brand-link {
        display: flex;
        align-items: center;
        min-width: 0;
    }

    .wg-brand-link:focus-visible {
        outline: var(--wg-focus-ring);
        outline-offset: var(--wg-focus-ring-offset);
        border-radius: var(--wg-radius-sm);
    }
</style>
