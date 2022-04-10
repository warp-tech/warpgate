<script lang="ts">
import { faSignOut } from '@fortawesome/free-solid-svg-icons'
import { api } from 'lib/api'
import { authenticatedUsername } from 'lib/store'
import Fa from 'svelte-fa'

import logo from '../public/assets/logo.svg'

import Router, { link, push } from 'svelte-spa-router'
import active from 'svelte-spa-router/active'
import { wrap } from 'svelte-spa-router/wrap'

let version = ''

async function init () {
    const info = await api.getInfo()
    version = info.version
    authenticatedUsername.set(info.username ?? null)
    if (!info.username) {
        push('/login')
    }
}

async function logout () {
    await api.logout()
    authenticatedUsername.set(null)
    push('/login')
}

init()

const routes = {
    '/': wrap({
        asyncComponent: () => import('./Home.svelte')
    }),
    '/login': wrap({
        asyncComponent: () => import('./Login.svelte')
    }),
    '/sessions/:id': wrap({
        asyncComponent: () => import('./Session.svelte')
    }),
    '/recordings/:id': wrap({
        asyncComponent: () => import('./Recording.svelte')
    }),
    '/tickets': wrap({
        asyncComponent: () => import('./Tickets.svelte')
    }),
    '/tickets/create': wrap({
        asyncComponent: () => import('./CreateTicket.svelte')
    }),
    '/targets': wrap({
        asyncComponent: () => import('./Targets.svelte')
    }),
    '/ssh': wrap({
        asyncComponent: () => import('./SSH.svelte')
    }),
}
</script>

<div class="app container">
    <header>
        <a use:link use:active href="/" class="d-flex">
            <img class="logo" src={logo} alt="Logo" />
        </a>
        {#if $authenticatedUsername}
            <a use:link use:active href="/">Sessions</a>
            <a use:link use:active href="/targets">Targets</a>
            <a use:link use:active href="/tickets">Tickets</a>
            <a use:link use:active href="/ssh">SSH</a>
        {/if}
        {#if $authenticatedUsername}
        <div class="username">
            <!-- {$authenticatedUsername} -->
        </div>
        <button class="btn btn-link" on:click={logout}>
            <Fa icon={faSignOut} fw />
        </button>
        {/if}
    </header>
    <main>
        <Router {routes}/>
    </main>
    <footer>
        {version}
    </footer>
</div>

<style lang="scss">
    @import "./vars";

    .app {
        min-height: 100vh;
        display: flex;
        flex-direction: column;
    }

    .logo {
        width: 40px;
        padding-top: 2px;
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
        border-bottom: 1px solid rgba($body-color, .75);

        a, .logo {
            font-size: 1.5rem;
        }

        a:not(:first-child) {
            margin-left: 15px;
        }

        .username {
            margin-left: auto;
        }
    }

    footer {
        display: flex;
        padding: 10px 0;
        margin: 20px 0 10px;
        border-top: 1px solid rgba($body-color, .75);
    }
</style>
