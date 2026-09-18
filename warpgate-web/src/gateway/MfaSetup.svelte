<script lang="ts">
    /**
     * Multi-factor setup — screen 14. Migrated in place.
     *
     * Behaviour preserved: addMyOtp with the generated secret, then
     * reloadServerInfo (which clears needsMfaSetup and so releases the route
     * guard) and push('/'). The order matters — navigating before the reload
     * would bounce straight back here, because requireLogin still sees
     * needsMfaSetup.
     *
     * The TOTP modal now points at the migrated one, so this flow inherits
     * the 6c security fix: the shared secret comes from
     * crypto.getRandomValues rather than Math.random().
     */
    import CreateOtpModal from 'admin/screens/user-detail/credentials/CreateOtpModal.svelte'
    import { reloadServerInfo, serverInfo } from 'gateway/lib/store'
    import { push } from 'svelte-spa-router'
    import Button from 'ui/Button.svelte'
    import Callout from 'ui/Callout.svelte'
    import { api } from './lib/api'

    let creatingOtpCredential = $state(false)

    async function createOtp(secretKey: number[]) {
        await api.addMyOtp({ newOtpCredential: { secretKey } })
        // Reload first: the route guard reads needsMfaSetup, so navigating
        // before this would bounce straight back here.
        await reloadServerInfo()
        push('/')
    }
</script>

<div class="head">
    <h1>Set up two-factor authentication</h1>
</div>

<Callout title="Required before you can continue">
    This server requires a second authentication factor. Once it is set up you
    will be taken to your targets.
</Callout>

<div class="action">
    <Button variant="primary" onclick={() => (creatingOtpCredential = true)}>
        Set up one-time password
    </Button>
</div>

{#if creatingOtpCredential && $serverInfo?.username}
    <CreateOtpModal
        bind:isOpen={creatingOtpCredential}
        username={$serverInfo.username}
        create={createOtp}
    />
{/if}

<style>
    .head {
        margin-bottom: var(--wg-space-lg);
    }

    h1 {
        margin: 0;
        font: var(--wg-text-headline-lg);
    }

    .action {
        display: flex;
        margin-top: var(--wg-space-xl);
    }

    @media (max-width: 640px) {
        h1 {
            font: var(--wg-text-headline-lg-mobile);
        }
    }
</style>
