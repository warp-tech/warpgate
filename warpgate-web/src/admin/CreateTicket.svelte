<script lang="ts">
import { api, User, Target, TicketAndSecret } from 'admin/lib/api'
import AsyncButton from 'common/AsyncButton.svelte'
import ConnectionInstructions from 'common/ConnectionInstructions.svelte'
import { TargetKind } from 'gateway/lib/api'
import { link } from 'svelte-spa-router'
import { Alert, FormGroup } from 'sveltestrap'
import { firstBy } from 'thenby'

let error: Error|null = null
let targets: Target[]|undefined
let users: User[]|undefined
let selectedTarget: Target|undefined
let selectedUser: User|undefined
let selectedExpiry: string|undefined
let result: TicketAndSecret|undefined

async function load () {
    [targets, users] = await Promise.all([
        api.getTargets(),
        api.getUsers(),
    ])
    targets = targets.filter(x => x.options.kind !== TargetKind.WebAdmin)
    targets.sort(firstBy('name'))
    users.sort(firstBy('username'))
}

load().catch(e => {
    error = e
})

async function create () {
    if (!selectedTarget || !selectedUser) {
        return
    }
    try {
        result = await api.createTicket({
            createTicketRequest: {
                username: selectedUser.username,
                targetName: selectedTarget.name,
                expiry: selectedExpiry ? new Date(selectedExpiry) : undefined,
            },
        })
    } catch (err) {
        error = err
    }
}

</script>

{#if error}
<Alert color="danger">{error}</Alert>
{/if}

{#if result}
    <div class="page-summary-bar">
        <h1>Ticket created</h1>
    </div>

    <Alert color="warning" fade={false}>
        The secret is only shown once - you won't be able to see it again.
    </Alert>

    {#if selectedTarget && selectedUser}
    <ConnectionInstructions
        targetName={selectedTarget.name}
        targetKind={TargetKind[selectedTarget.options.kind]}
        username={selectedUser.username}
        targetExternalHost={selectedTarget.options['externalHost']}
        ticketSecret={result.secret}
    />
    {/if}

    <a
        class="btn btn-secondary"
        href="/tickets"
        use:link
    >Done</a>
{:else}
<div class="narrow-page">
    <div class="page-summary-bar">
        <h1>Create an access ticket</h1>
    </div>

    {#if users}
    <FormGroup floating label="Authorize as user">
        <select bind:value={selectedUser} class="form-control">
            {#each users as user}
                <option value={user}>
                    {user.username}
                </option>
            {/each}
        </select>
    </FormGroup>
    {/if}

    {#if targets}
    <FormGroup floating label="Target">
        <select bind:value={selectedTarget} class="form-control">
            {#each targets as target}
                <option value={target}>
                    {target.name}
                </option>
            {/each}
        </select>
    </FormGroup>
    {/if}

    <FormGroup floating label="Expiry (optional)">
        <input type="datetime-local" bind:value={selectedExpiry} class="form-control"/>
    </FormGroup>

    <AsyncButton
        outline
        click={create}
    >Create ticket</AsyncButton>
</div>
{/if}
