<script lang="ts">
    import NavListItem from 'common/NavListItem.svelte'
    import { serverInfo } from 'gateway/lib/store'
</script>

<div class="page-summary-bar">
    {#if $serverInfo}
        <h1>{$serverInfo.username}</h1>
    {/if}
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

{#if $serverInfo?.ticketSelfServiceEnabled}
    <NavListItem
        title="Ticket requests"
        description="Request and manage self-service access tickets"
        href="/ticket-requests"
    />
{/if}
