<script lang="ts">
import { faSignOut } from '@fortawesome/free-solid-svg-icons'
import { Alert, Spinner } from 'sveltestrap'
import Fa from 'svelte-fa'
import { api } from 'gateway/lib/api'
import { reloadServerInfo, serverInfo } from 'gateway/lib/store'
import ThemeSwitcher from 'common/ThemeSwitcher.svelte'
import Login from './Login.svelte'
import TargetList from './TargetList.svelte'
import Logo from 'common/Logo.svelte'

let redirecting = false

async function init () {
    await reloadServerInfo()
}

async function logout () {
    await api.logout()
    await reloadServerInfo()
}

function onPageResume () {
    redirecting = false
    init()
}

init()
</script>

<svelte:window on:pageshow={onPageResume}/>

<div class="container">
{#await init()}
    <Spinner />
{:then _}
    {#if redirecting}
        <Spinner />
    {:else}
        <div class="d-flex align-items-center mt-5 mb-5">
            <div class="logo">
                <Logo />
            </div>

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
            {#if $serverInfo?.username}
                <TargetList
                on:navigation={() => redirecting = true} />
            {:else}
                <Login />
            {/if}
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
