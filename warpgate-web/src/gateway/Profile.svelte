<script lang="ts">
    import { Alert, Input } from '@sveltestrap/sveltestrap'
    import { stringifyError } from 'common/errors'
    import Loadable from 'common/Loadable.svelte'
    import NavListItem from 'common/NavListItem.svelte'
    import { api, type UserPreferences } from 'gateway/lib/api'
    import { serverInfo } from 'gateway/lib/store'

    let preferences: UserPreferences | undefined = $state()
    let error: string | undefined = $state()
    const preferencesPromise = api.getMyPreferences()

    async function setShowSessionMenu(showSessionMenu: boolean) {
        try {
            error = undefined
            preferences = await api.updateMyPreferences({
                updateUserPreferences: { showSessionMenu },
            })
        } catch (err) {
            error = await stringifyError(err)
        }
    }
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

<h4 class="mt-5">Preferences</h4>

<Loadable promise={preferencesPromise} bind:value={preferences}>
    {#snippet children(preferences)}
        <Input
            id="showSessionMenu"
            type="switch"
            label="Show the Warpgate menu button on web targets"
            checked={preferences.showSessionMenu && !preferences.sessionMenuDisabledGlobally}
            disabled={preferences.sessionMenuDisabledGlobally}
            onchange={e =>
                setShowSessionMenu((e.currentTarget as HTMLInputElement).checked)}
        />
        {#if preferences.sessionMenuDisabledGlobally}
            <small class="text-muted">
                Turned off for everyone by the administrator
            </small>
        {/if}
    {/snippet}
</Loadable>

{#if error}
    <Alert color="danger">{error}</Alert>
{/if}
