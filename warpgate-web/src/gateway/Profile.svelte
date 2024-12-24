<script lang="ts">
    import { serverInfo } from 'gateway/lib/store'
    import NavListItem from 'common/NavListItem.svelte'
</script>

<div class="page-summary-bar">
    <h1>{$serverInfo!.username}</h1>
</div>

<NavListItem
    title="API tokens"
    description="Manage your API tokens"
    href="/profile/api-tokens"
/>

{#if $serverInfo}
    {#if $serverInfo.ownCredentialManagementAllowed}
        <NavListItem
            title="Credentials"
            description="Manage your passwords and keys"
            href="/profile/credentials"
        />
    {/if}
{/if}
