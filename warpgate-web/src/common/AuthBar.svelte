<script lang="ts">
import { faSignOut } from '@fortawesome/free-solid-svg-icons'
import Fa from 'svelte-fa'

import { api } from 'gateway/lib/api'
import { serverInfo, reloadServerInfo } from 'gateway/lib/store'
import { Button, Dropdown, DropdownItem, DropdownMenu, DropdownToggle } from '@sveltestrap/sveltestrap'

async function logout () {
    await api.logout()
    await reloadServerInfo()
    location.href = '/@warpgate'
}

async function singleLogout () {
    const response = await api.initiateSsoLogout()
    location.href = response.url
}
</script>

{#if $serverInfo?.username}
    <div class="ms-auto">
        <a href="/@warpgate/#/profile">
            {$serverInfo.username}
        </a>
        {#if $serverInfo.authorizedViaTicket}
            <span class="ml-2">(ticket auth)</span>
        {/if}
    </div>

    {#if $serverInfo?.authorizedViaSsoWithSingleLogout}
        <Dropdown>
            <DropdownToggle color="link" title="Log out options">
                <Fa icon={faSignOut} fw />
            </DropdownToggle>
            <DropdownMenu right={true}>
                <DropdownItem on:click={logout}>
                    <Fa icon={faSignOut} fw />
                    Log out of Warpgate
                </DropdownItem>
                <DropdownItem on:click={singleLogout}>
                    <Fa icon={faSignOut} fw />
                    Log out everywhere
                </DropdownItem>
            </DropdownMenu>
        </Dropdown>
    {:else}
        <Button color="link" on:click={logout} title="Log out" class="p-0 ms-2">
            <Fa icon={faSignOut} fw />
        </Button>
    {/if}
{/if}
