<script lang="ts">
    import { faArrowRight } from '@fortawesome/free-solid-svg-icons'
    import { Button } from '@sveltestrap/sveltestrap'
    import CreateOtpModal from 'admin/CreateOtpModal.svelte'
    import { reloadServerInfo, serverInfo } from 'gateway/lib/store'
    import Fa from 'svelte-fa'
    import { push } from 'svelte-spa-router'
    import { api } from './lib/api'

    let creatingOtpCredential = $state(false)

    async function createOtp(secretKey: number[]) {
        await api.addMyOtp({
            newOtpCredential: {
                secretKey,
            },
        })
        await reloadServerInfo()
        push('/')
    }
</script>

<div class="page-summary-bar">
    <h1>Multi-factor authentication setup</h1>
</div>

<p>
    Before you can use Warpgate, you need to add a second authentication factor
    to protect your account.
</p>

<Button
    color="primary"
    class="d-flex align-items-center align-self-start gap-2"
    onclick={e => {
        creatingOtpCredential = true
        e.preventDefault()
    }}
>
    Set up one-time password
    <Fa icon={faArrowRight} />
</Button>

{#if creatingOtpCredential && $serverInfo?.username}
    <CreateOtpModal
        bind:isOpen={creatingOtpCredential}
        username={$serverInfo.username}
        create={createOtp}
    />
{/if}
