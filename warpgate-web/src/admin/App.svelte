<script lang="ts">
    import AuthBar from 'common/AuthBar.svelte'
    import Brand from 'common/Brand.svelte'
    import Loadable from 'common/Loadable.svelte'
    import Redirect from 'common/Redirect.svelte'
    import RequestsButton from 'common/RequestsButton.svelte'
    import ThemeSwitcher from 'common/ThemeSwitcher.svelte'
    import { reloadServerInfo, serverInfo } from 'gateway/lib/store'
    import { get } from 'svelte/store'
    import Router, { link, type WrappedComponent } from 'svelte-spa-router'
    import active from 'svelte-spa-router/active'
    import { wrap } from 'svelte-spa-router/wrap'
    import AnalyticsConsentModal from './AnalyticsConsentModal.svelte'

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

    async function init() {
        await reloadServerInfo()
        if (!get(serverInfo)?.username) {
            // Not logged in: redirect to the (gateway) login page, preserving this admin
            // URL — hash route included — as `next` so we return exactly here afterwards.
            // (The admin shell is no longer server-gated, so this runs client-side where
            // the SPA hash route is known.)
            const next = location.pathname + location.hash
            location.assign(
                `/@warpgate#/login?next=${encodeURIComponent(next)}`,
            )
        }
    }

    const initPromise = init()

    const routes: Record<string, WrappedComponent> = {
        '/': wrap({
            component: Redirect,
            props: { to: '/status/sessions' },
        }),
        '/status/recordings/:id': wrap({
            asyncComponent: () => import('./status/Recording.svelte'),
        }),
        '/status': wrap({
            asyncComponent: () => import('./status/Status.svelte'),
        }),
        '/log': wrap({
            asyncComponent: () => import('./Log.svelte'),
        }),
        '/log/user/:id': wrap({
            asyncComponent: () => import('./Log.svelte'),
            props: {
                filterKind: 'user',
            },
        }),
        '/log/access-role/:id': wrap({
            asyncComponent: () => import('./Log.svelte'),
            props: {
                filterKind: 'access-role',
            },
        }),
        '/log/admin-role/:id': wrap({
            asyncComponent: () => import('./Log.svelte'),
            props: {
                filterKind: 'admin-role',
            },
        }),
        '/config': wrap({
            asyncComponent: () => import('./config/Config.svelte'),
        }),
    }
    // biome-ignore lint/style/noNonNullAssertion: x
    routes['/config/*'] = routes['/config']!
    // biome-ignore lint/style/noNonNullAssertion: x
    routes['/status/*'] = routes['/status']!
</script>

<Loadable promise={initPromise}>
    <div class="app container-lg">
        <header>
            <a href="/@warpgate" class="d-flex logo-link me-4">
                <Brand />
            </a>
            {#if $serverInfo?.username}
                <a use:link use:active href="/status/sessions">Status</a>
                <a use:link use:active href="/config">Config</a>
                <a use:link use:active href="/log">Log</a>
            {/if}
            <span class="ms-3"></span>
            <div class="ms-auto d-flex align-items-center">
                <RequestsButton collapsed class="me-4" />
                <AuthBar />
            </div>
        </header>
        <main>
            <Router {routes} />
        </main>

        <footer class="mt-5">
            <span class="me-auto ms-3">
                {$serverInfo?.version}
            </span>
            <ThemeSwitcher />
        </footer>
    </div>
</Loadable>

{#if showAnalyticsModal}
    <AnalyticsConsentModal bind:isOpen={showAnalyticsModal} />
{/if}

<style lang="scss">
    @media (max-width: 767px) {
        .logo-link {
            display: none !important;
        }
    }

    .app {
        min-height: 100vh;
        display: flex;
        flex-direction: column;
    }

    header, footer {
        flex: none;
    }

    main {
        flex: 1 0 0;
    }

    header {
        display: flex;
        align-items: center;
        padding: 7px 0;
        margin: 10px 0 20px;

        a {
            font-size: 1.5rem;
            margin-right: 15px;
        }
    }
</style>
