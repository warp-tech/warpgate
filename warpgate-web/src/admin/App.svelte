<script lang="ts">
import { serverInfo, reloadServerInfo } from 'gateway/lib/store'

import Router, { link } from 'svelte-spa-router'
import active from 'svelte-spa-router/active'
import { wrap } from 'svelte-spa-router/wrap'
import ThemeSwitcher from 'common/ThemeSwitcher.svelte'
import DelayedSpinner from 'common/DelayedSpinner.svelte'
import AuthBar from 'common/AuthBar.svelte'
import Brand from 'common/Brand.svelte'
    import { Button } from '@sveltestrap/sveltestrap';
    import Badge from 'common/sveltestrap-s5-ports/Badge.svelte';

async function init () {
    await reloadServerInfo()
}

init()

const routes = {
    '/': wrap({
        asyncComponent: () => import('./Home.svelte') as any,
    }),
    '/sessions/:id': wrap({
        asyncComponent: () => import('./Session.svelte') as any,
    }),
    '/recordings/:id': wrap({
        asyncComponent: () => import('./Recording.svelte') as any,
    }),
    '/targets/create': wrap({
        asyncComponent: () => import('./CreateTarget.svelte') as any,
    }),
    '/targets/:id': wrap({
        asyncComponent: () => import('./Target.svelte') as any,
    }),
    '/roles/create': wrap({
        asyncComponent: () => import('./CreateRole.svelte') as any,
    }),
    '/roles/:id': wrap({
        asyncComponent: () => import('./Role.svelte') as any,
    }),
    '/users/create': wrap({
        asyncComponent: () => import('./CreateUser.svelte') as any,
    }),
    '/users/:id': wrap({
        asyncComponent: () => import('./User.svelte') as any,
    }),
    '/log': wrap({
        asyncComponent: () => import('./Log.svelte') as any,
    }),
    '/config': wrap({
        asyncComponent: () => import('./config/Config.svelte') as any,
    }),
    '/config/parameters': wrap({
        asyncComponent: () => import('./config/Parameters.svelte') as any,
    }),
    '/config/users': wrap({
        asyncComponent: () => import('./config/Users.svelte') as any,
    }),
    '/config/roles': wrap({
        asyncComponent: () => import('./config/Roles.svelte') as any,
    }),
    '/config/targets': wrap({
        asyncComponent: () => import('./config/Targets.svelte') as any,
    }),
    '/config/ssh': wrap({
        asyncComponent: () => import('./config/SSHKeys.svelte') as any,
    }),
    '/config/tickets': wrap({
        asyncComponent: () => import('./config/Tickets.svelte') as any,
    }),
    '/config/tickets/create': wrap({
        asyncComponent: () => import('./CreateTicket.svelte') as any,
    }),
}
</script>

{#await init()}
    <DelayedSpinner />
{:then}
    <div class="app container">
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
                v{$serverInfo?.version}
            </span>
            <ThemeSwitcher />
        </footer>
    </div>
{/await}

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
