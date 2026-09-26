<script lang="ts">
    import { Alert } from '@sveltestrap/sveltestrap'
    import { serverInfo } from 'gateway/lib/store'
    import CredentialManager from './CredentialManager.svelte'
</script>

<div class="page-summary-bar">
    <h1>Credentials</h1>
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
