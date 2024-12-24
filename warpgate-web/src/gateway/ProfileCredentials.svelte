<script lang="ts">
    import { serverInfo } from 'gateway/lib/store'
    import Alert from 'common/sveltestrap-s5-ports/Alert.svelte'
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
