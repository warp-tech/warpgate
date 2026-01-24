<script lang="ts">
import { api, type User, type Target, type TicketAndSecret } from 'admin/lib/api'
import AsyncButton from 'common/AsyncButton.svelte'
import ConnectionInstructions from 'common/ConnectionInstructions.svelte'
import { TargetKind } from 'gateway/lib/api'
import { link } from 'svelte-spa-router'
import { FormGroup } from '@sveltestrap/sveltestrap'
import { firstBy } from 'thenby'
import { stringifyError } from 'common/errors'
import Alert from 'common/sveltestrap-s5-ports/Alert.svelte'

let error: string|null = $state(null)
let targets: Target[]|undefined = $state()
let users: User[]|undefined = $state()
let selectedTarget: Target|undefined = $state()
let selectedUser: User|undefined = $state()
let selectedExpiry: string|undefined = $state()
let selectedNumberOfUses: number|undefined = $state()
let result: TicketAndSecret|undefined = $state()
let selectedDescription: string = $state('')

async function load () {
    [targets, users] = await Promise.all([
        api.getTargets(),
        api.getUsers(),
    ])
    targets = targets.filter(x => x.options.kind !== TargetKind.WebAdmin)
    targets.sort(firstBy('name'))
    users.sort(firstBy('username'))
}

load().catch(async e => {
    error = await stringifyError(e)
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
                numberOfUses: selectedNumberOfUses,
                description: selectedDescription,
            },
        })
    } catch (err) {
        error = await stringifyError(err)
    }
}

</script>

<div class="container-max-md">
    {#if error}
    <Alert color="danger">{error}</Alert>
    {/if}

    {#if result}
        <div class="page-summary-bar">
            <h1>ticket created</h1>
        </div>

        <Alert color="warning" fade={false} class="mb-3">
            The secret is only shown once - you won't be able to see it again.
        </Alert>

        {#if selectedTarget && selectedUser}
        <ConnectionInstructions
            targetName={selectedTarget.name}
            targetKind={TargetKind[selectedTarget.options.kind]}
            username={selectedUser.username}
            targetExternalHost={selectedTarget.options.kind === 'Http' ? selectedTarget.options.externalHost : undefined}
            ticketSecret={result.secret}
            targetDefaultDatabaseName={
                (selectedTarget.options.kind === TargetKind.MySql || selectedTarget.options.kind === TargetKind.Postgres)
                    ? selectedTarget.options.defaultDatabaseName : undefined}
        />
        {/if}

        <a
            class="btn btn-secondary"
            href="/config/tickets"
            use:link
        >Done</a>
    {:else}
    <div class="narrow-page">
        <div class="page-summary-bar">
            <h1>create an access ticket</h1>
        </div>

        {#if users}
        <FormGroup floating label="Authorize as user">
            <select bind:value={selectedUser} class="form-control">
                {#each users as user (user.id)}
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
                {#each targets as target (target.id)}
                    <option value={target}>
                        {target.name}
                    </option>
                {/each}
            </select>
        </FormGroup>
        {/if}

        <FormGroup floating label="Description">
            <input type="text" bind:value={selectedDescription} class="form-control" placeholder="Optional description"/>
        </FormGroup>

        <FormGroup floating label="Expiry (optional)">
            <input type="datetime-local" bind:value={selectedExpiry} class="form-control"/>
        </FormGroup>

        <FormGroup floating label="Number of uses (optional)">
            <input type="number" min="1" bind:value={selectedNumberOfUses} class="form-control"/>
        </FormGroup>

        <AsyncButton
        color="primary"
            click={create}
        >Create ticket</AsyncButton>
    </div>
    {/if}
</div>
