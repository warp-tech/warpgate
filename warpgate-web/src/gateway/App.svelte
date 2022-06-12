<script lang="ts">
import { faSignOut } from '@fortawesome/free-solid-svg-icons'
import { api } from 'gateway/lib/api'
import { authenticatedUsername } from 'gateway/lib/store'
import Fa from 'svelte-fa'

import logo from '../../public/assets/logo.svg'

import Router, { link, push } from 'svelte-spa-router'
import active from 'svelte-spa-router/active'
import { wrap } from 'svelte-spa-router/wrap'
import Login from './Login.svelte'
import TargetList from './TargetList.svelte'
import { Spinner } from 'sveltestrap'

let version = ''
let loading = true
let redirecting = false

async function init () {
    const info = await api.getInfo()
    version = info.version
    authenticatedUsername.set(info.username ?? null)
    loading = false
}

async function logout () {
    await api.logout()
    authenticatedUsername.set(null)
    push('/')
}

function onPageResume () {
    redirecting = false
    init()
}

init()

// const routes = {
//     '/': wrap({
//         asyncComponent: () => import('./Home.svelte'),
//     }),
// }
</script>

<svelte:window on:pageshow={onPageResume}/>

{#if loading || redirecting}
    <Spinner />
{:else}
    {#if $authenticatedUsername}
        <button class="btn btn-link" on:click={logout}>
            <Fa icon={faSignOut} fw />
        </button>

        <TargetList on:navigation={() => redirecting = true} />

        Home
    {:else}
        <Login />
    {/if}

    {version}
{/if}
