<script lang="ts">
    import { serverInfo } from 'gateway/lib/store'
    import Alert from 'common/Alert.svelte'
    import CredentialManager from './CredentialManager.svelte'
</script>

<div class="page-summary-bar">
    <div>
        <h1>{$serverInfo!.username}</h1>
        <div class="text-muted">User</div>
    </div>
</div>

{#if $serverInfo}
    {#if $serverInfo.ownCredentialManagementAllowed}
        <CredentialManager />
    {:else}
        <Alert color="info">
            Credential management is disabled by your administrator
        </Alert>
    {/if}
{/if}
