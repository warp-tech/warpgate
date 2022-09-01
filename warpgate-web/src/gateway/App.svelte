<script lang="ts">
import { faSignOut } from '@fortawesome/free-solid-svg-icons'
import { Alert } from 'sveltestrap'
import Fa from 'svelte-fa'
import Router, { push, RouteDetail } from 'svelte-spa-router'
import { wrap } from 'svelte-spa-router/wrap'
import { get } from 'svelte/store'
import { api } from 'gateway/lib/api'
import { reloadServerInfo, serverInfo } from 'gateway/lib/store'
import ThemeSwitcher from 'common/ThemeSwitcher.svelte'
import Logo from 'common/Logo.svelte'
import DelayedSpinner from 'common/DelayedSpinner.svelte'

let redirecting = false
let serverInfoPromise = reloadServerInfo()

async function init () {
    await serverInfoPromise
}

async function logout () {
    await api.logout()
    await reloadServerInfo()
    push('/login')
}

function onPageResume () {
    redirecting = false
    init()
}

async function requireLogin (detail: RouteDetail) {
    await serverInfoPromise
    if (!get(serverInfo)?.username) {
        let url = detail.location
        if (detail.querystring) {
            url += '?' + detail.querystring
        }
        push('/login?next=' + encodeURIComponent(url))
        return false
    }
    return true
}

const routes = {
    '/': wrap({
        asyncComponent: () => import('./TargetList.svelte'),
        props: {
            'on:navigation': () => redirecting = true,
        },
        conditions: [requireLogin],
    }),
    '/login': wrap({
        asyncComponent: () => import('./Login.svelte'),
    }),
    '/login/:stateId': wrap({
        asyncComponent: () => import('./OutOfBandAuth.svelte'),
        conditions: [requireLogin],
    }),
}

init()
</script>

<svelte:window on:pageshow={onPageResume}/>

<div class="container">
{#await init()}
    <DelayedSpinner />
{:then _}
    {#if redirecting}
        <DelayedSpinner />
    {:else}
        <div class="d-flex align-items-center mt-5 mb-5">
            <a class="logo" href="/@warpgate">
                <Logo />
            </a>

            {#if $serverInfo?.username}
                <div class="ms-auto">
                    {$serverInfo.username}
                    {#if $serverInfo.authorizedViaTicket}
                        <span class="ml-2">(ticket auth)</span>
                    {/if}
                </div>
                <button class="btn btn-link" on:click={logout} title="Log out">
                    <Fa icon={faSignOut} fw />
                </button>
            {/if}
        </div>

        <main>
            <Router {routes}/>
        </main>

        <footer class="mt-5">
            <span class="me-auto">
                v{$serverInfo?.version}
            </span>
            <ThemeSwitcher />
        </footer>
    {/if}
{:catch error}
    <Alert color="danger">{error}</Alert>
{/await}
</div>

<style lang="scss">
    .container {
        width: 500px;
        max-width: 100vw;
    }

    .logo {
        width: 5rem;
        margin: 0 -0.5rem;
    }
</style>
