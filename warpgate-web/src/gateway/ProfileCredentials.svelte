<script lang="ts">
    /**
     * Credentials page — screen 14. Migrated in place.
     *
     * Behaviour preserved exactly: the manager renders only when
     * ownCredentialManagementAllowed, and otherwise the page says who turned
     * it off rather than showing an empty screen.
     */
    import { serverInfo } from 'gateway/lib/store'
    import Callout from 'ui/Callout.svelte'
    import CredentialManager from './CredentialManager.svelte'
</script>

<div class="head">
    <h1>Credentials</h1>
    <p class="lede">Passwords, one-time passwords, keys and certificates.</p>
</div>

{#if $serverInfo}
    {#if $serverInfo.ownCredentialManagementAllowed}
        <CredentialManager />
    {:else}
        <Callout title="Credential management is turned off">
            Your administrator manages credentials for this account. Contact
            them to change a password or add a key.
        </Callout>
    {/if}
{/if}

<style>
    .head {
        margin-bottom: var(--wg-space-xl);
    }

    h1 {
        margin: 0;
        font: var(--wg-text-headline-lg);
    }

    .lede {
        margin: var(--wg-space-xs) 0 0;
        color: var(--wg-text-muted);
        font: var(--wg-text-body-md);
    }

    @media (max-width: 640px) {
        h1 {
            font: var(--wg-text-headline-lg-mobile);
        }
    }
</style>
