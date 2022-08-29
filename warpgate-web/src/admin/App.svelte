<script lang="ts">
import { faSignOut } from '@fortawesome/free-solid-svg-icons'
import { api } from 'gateway/lib/api'
import { serverInfo, reloadServerInfo } from 'gateway/lib/store'
import Fa from 'svelte-fa'

import Router, { link } from 'svelte-spa-router'
import active from 'svelte-spa-router/active'
import { wrap } from 'svelte-spa-router/wrap'
import ThemeSwitcher from 'common/ThemeSwitcher.svelte'
import Logo from 'common/Logo.svelte'
import DelayedSpinner from 'common/DelayedSpinner.svelte'

async function init () {
    await reloadServerInfo()
}

async function logout () {
    await api.logout()
    await reloadServerInfo()
    location.href = '/@warpgate'
}

init()

const routes = {
    '/': wrap({
        asyncComponent: () => import('./Home.svelte'),
    }),
    '/sessions/:id': wrap({
        asyncComponent: () => import('./Session.svelte'),
    }),
    '/recordings/:id': wrap({
        asyncComponent: () => import('./Recording.svelte'),
    }),
    '/tickets': wrap({
        asyncComponent: () => import('./Tickets.svelte'),
    }),
    '/tickets/create': wrap({
        asyncComponent: () => import('./CreateTicket.svelte'),
    }),
    '/config': wrap({
        asyncComponent: () => import('./Config.svelte'),
    }),
    '/targets/create': wrap({
        asyncComponent: () => import('./CreateTarget.svelte'),
    }),
    '/targets/:id': wrap({
        asyncComponent: () => import('./Target.svelte'),
    }),
    '/roles/create': wrap({
        asyncComponent: () => import('./CreateRole.svelte'),
    }),
    '/roles/:id': wrap({
        asyncComponent: () => import('./Role.svelte'),
    }),
    '/users/create': wrap({
        asyncComponent: () => import('./CreateUser.svelte'),
    }),
    '/users/:id': wrap({
        asyncComponent: () => import('./User.svelte'),
    }),
    '/ssh': wrap({
        asyncComponent: () => import('./SSH.svelte'),
    }),
    '/log': wrap({
        asyncComponent: () => import('./Log.svelte'),
    }),
}
</script>

{#await init()}
    <DelayedSpinner />
{:then}
    <div class="app container">
        <header>
            <a href="/@warpgate" class="d-flex">
                <div class="logo">
                    <Logo />
                </div>
            </a>
            {#if $serverInfo?.username}
                <a use:link use:active href="/">Sessions</a>
                <a use:link use:active href="/config">Config</a>
                <a use:link use:active href="/tickets">Tickets</a>
                <a use:link use:active href="/ssh">SSH</a>
                <a use:link use:active href="/log">Log</a>
            {/if}
            {#if $serverInfo?.username}
            <div class="username ms-auto">
                {$serverInfo?.username}
            </div>
            <button class="btn btn-link" on:click={logout} title="Log out">
                <Fa icon={faSignOut} fw />
            </button>
            {/if}
        </header>
        <main>
            <Router {routes}/>
        </main>

        <footer class="mt-5">
            <span class="me-auto">
                v{$serverInfo?.version}
            </span>
            <ThemeSwitcher />
        </footer>
    </div>
{/await}

<style lang="scss">
    .app {
        min-height: 100vh;
        display: flex;
        flex-direction: column;
    }

    .logo {
        width: 40px;
        padding-top: 2px;
        display: flex;
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
        padding: 10px 0;
        margin: 10px 0 20px;

        a, .logo {
            font-size: 1.5rem;
        }

        a:not(:first-child) {
            margin-left: 15px;
        }
    }
</style>
