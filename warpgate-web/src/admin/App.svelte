<script lang="ts">
    import { faGithub } from '@fortawesome/free-brands-svg-icons'
    import { faBriefcase, faNavicon } from '@fortawesome/free-solid-svg-icons'
    import { Alert, Button } from '@sveltestrap/sveltestrap'
    import AuthBar from 'common/AuthBar.svelte'
    import Brand from 'common/Brand.svelte'
    import Loadable from 'common/Loadable.svelte'
    import Redirect from 'common/Redirect.svelte'
    import RequestsButton from 'common/RequestsButton.svelte'
    import Sidebar from 'common/Sidebar.svelte'
    import { sidebar } from 'common/sidebarState.svelte'
    import ThemeSwitcher from 'common/ThemeSwitcher.svelte'
    import { reloadServerInfo, serverInfo } from 'gateway/lib/store'
    import { get } from 'svelte/store'
    import Fa from 'svelte-fa'
    import Router, {
        link,
        router,
        type WrappedComponent,
    } from 'svelte-spa-router'
    import active from 'svelte-spa-router/active'
    import { wrap } from 'svelte-spa-router/wrap'
    import AnalyticsConsentModal from './AnalyticsConsentModal.svelte'
    import { ADMIN_PERMISSIONS } from './lib/store'

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
        const adminPermissions = get(serverInfo)?.adminPermissions
        if (
            !get(serverInfo)?.username ||
            !adminPermissions ||
            !ADMIN_PERMISSIONS.some(p => adminPermissions[p.key])
        ) {
            // Not logged in: redirect to the (gateway) login page, preserving this admin
            // URL — hash route included — as `next` so we return exactly here afterwards.
            // (The admin shell is no longer server-gated, so this runs client-side where
            // the SPA hash route is known.)
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

    const routes: Record<string, WrappedComponent> = {
        '/': wrap({
            component: Redirect,
            props: { to: '/status/sessions' },
        }),
        '/status/recordings/:id': wrap({
            asyncComponent: () => import('./status/Recording.svelte'),
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
        '/manage': wrap({
            component: Redirect,
            props: { to: '/manage/targets' },
        }),
        '/manage/*': wrap({
            asyncComponent: () => import('./config/Manage.svelte'),
        }),
        '/config': wrap({
            component: Redirect,
            props: { to: '/config/parameters/auth' },
        }),
        '/config/*': wrap({
            asyncComponent: () => import('./config/Config.svelte'),
        }),
        '/status': wrap({
            component: Redirect,
            props: { to: '/status/sessions' },
        }),
        '/status/*': wrap({
            asyncComponent: () => import('./status/Status.svelte'),
        }),
    }

    const wideMode = $derived(router.location.startsWith('/log'))
</script>

<Loadable promise={initPromise}>
    <div
        class="app"
        class:container-lg={!wideMode}
        class:container-max={wideMode}
    >
        <header>
            {#if sidebar.items}
                <Button
                    color="link"
                    class="d-lg-none pe-3 ps-2"
                    aria-label="Menu"
                    onclick={() => (sidebar.open = true)}
                >
                    <Fa icon={faNavicon} />
                </Button>
            {/if}
            <a href="/@warpgate" class="d-flex logo-link me-4">
                <Brand />
            </a>
            {#if $serverInfo?.username}
                <a
                    class="navlink"
                    use:link
                    use:active={{ path: /^\/status\// }}
                    href="/status/sessions"
                >
                    Status
                </a>
                <a
                    class="navlink"
                    use:link
                    use:active={{ path: /^\/manage\// }}
                    href="/manage"
                >
                    Manage
                </a>
                <a
                    class="navlink"
                    use:link
                    use:active={{ path: /^\/config\// }}
                    href="/config"
                >
                    Config
                </a>
                <a class="navlink" use:link use:active href="/log">Log</a>
            {/if}
            <span class="ms-3"></span>
            <div class="ms-auto d-flex align-items-center">
                <RequestsButton collapsed class="me-4" />
                <AuthBar />
            </div>
        </header>
        <main>
            {#if $serverInfo?.configWarnings?.length}
                <Alert color="warning" fade={false} class="mb-3">
                    <strong>Issues found:</strong>
                    <ul class="mb-0 mt-2">
                        {#each $serverInfo.configWarnings as warning (warning)}
                            <li>{warning}</li>
                        {/each}
                    </ul>
                </Alert>
            {/if}
            <div class="d-flex">
                {#if sidebar.items}
                    <Sidebar />
                {/if}
                <div class="content">
                    <Router {routes} />
                </div>
            </div>
        </main>

        <footer class="d-flex mt-5 gap-3">
            <div>
                {$serverInfo?.version}
            </div>
            &middot;
            <div class="d-flex align-items-center gap-2">
                <Fa icon={faGithub} class="text-muted" />
                <a target="_blank" href="https://github.com/warp-tech/warpgate">
                    GitHub
                </a>
            </div>
            &middot;
            <div class="d-flex align-items-center gap-2">
                <Fa icon={faBriefcase} class="text-muted" />
                <a
                    target="_blank"
                    href="https://warpgate.null.page/for-business/?utm_source=app&utm_content=footer"
                >
                    Professional support
                </a>
            </div>
            <div class="me-auto"></div>
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

        &.container-max {
            margin: 0 30px;
        }
    }

    header, footer {
        flex: none;
    }

    .content {
        flex: 1 0 0;
        min-width: 0;
    }

    .navlink {
        margin-bottom: 2px;
        font-size: 1.25rem;
        margin-right: 15px;
    }

    main {
        flex: 1 0 0;
        min-width: 0;
        display: flex;
        flex-direction: column;
    }

    header {
        display: flex;
        align-items: center;
        padding: 7px 0;
        margin: 10px 0 20px;

    }
</style>
