<script lang="ts">
    import { serverInfo, reloadServerInfo } from 'gateway/lib/store'

    import Router, { link, type WrappedComponent } from 'svelte-spa-router'
    import active from 'svelte-spa-router/active'
    import { wrap } from 'svelte-spa-router/wrap'
    import ThemeSwitcher from 'common/ThemeSwitcher.svelte'
    import AuthBar from 'common/AuthBar.svelte'
    import Brand from 'common/Brand.svelte'
    import Loadable from 'common/Loadable.svelte'

    async function init () {
        await reloadServerInfo()
    }

    const initPromise = init()

    const routes: Record<string, WrappedComponent> = {
        '/': wrap({
            asyncComponent: () => import('./Home.svelte') as any,
        }),
        '/sessions/:id': wrap({
            asyncComponent: () => import('./Session.svelte') as any,
        }),
        '/recordings/:id': wrap({
            asyncComponent: () => import('./Recording.svelte') as any,
        }),
        '/log': wrap({
            asyncComponent: () => import('./Log.svelte') as any,
        }),
        '/config': wrap({
            asyncComponent: () => import('./config/Config.svelte') as any,
        }),
    }
    routes['/config/*'] = routes['/config']!
</script>

<Loadable promise={initPromise}>
    <div class="app container-lg">
        <header>
            <a href="/@warpgate" class="d-flex logo-link me-4">
                <Brand />
            </a>
            {#if $serverInfo?.username}
                <a use:link use:active href="/">Sessions</a>
                <a use:link use:active href="/config">Config</a>
                <a use:link use:active href="/log">Log</a>
            {/if}
            <span class="ms-3"></span>
            <AuthBar />
        </header>
        <main>
            <Router {routes}/>
        </main>

        <footer class="mt-5">
            <span class="me-auto ms-3">
                {$serverInfo?.version}
            </span>
            <ThemeSwitcher />
        </footer>
    </div>
</Loadable>

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
