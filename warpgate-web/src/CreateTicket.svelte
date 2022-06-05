<script lang="ts">
import { api, UserSnapshot, Target, TicketAndSecret } from 'lib/api'
import { link } from 'svelte-spa-router'
import { Alert, Button, FormGroup } from 'sveltestrap'
import { firstBy } from 'thenby'

let error: Error|null = null
let targets: Target[]|undefined
let users: UserSnapshot[]|undefined
let selectedTarget: Target|undefined
let selectedUser: UserSnapshot|undefined
let result: TicketAndSecret|undefined

async function load () {
    [targets, users] = await Promise.all([
        api.getTargets(),
        api.getUsers(),
    ])
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

    {#if selectedTarget?.ssh}
        <h3>Connection instructions</h3>

        <FormGroup floating label="SSH username">
            <input type="text" class="form-control" readonly value={'ticket-' + result.secret} />
        </FormGroup>

        <FormGroup floating label="Example command">
            <input type="text" class="form-control" readonly value={'ssh ticket-' + result.secret + '@warpgate-host -p warpgate-port'} />
        </FormGroup>
    {/if}

    <a
        class="btn btn-secondary"
        href="/tickets"
        use:link
    >Done</a>
{:else}
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

    <Button
        outline
        on:click={create}
    >Create ticket</Button>
{/if}
