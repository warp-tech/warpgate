<script lang="ts">
import { api, type Ticket } from 'admin/lib/api'
import { link } from 'svelte-spa-router'
import RelativeDate from './RelativeDate.svelte'
import Fa from 'svelte-fa'
import { faCalendarXmark, faCalendarCheck, faSquareXmark, faSquareCheck } from '@fortawesome/free-solid-svg-icons'
import { stringifyError } from 'common/errors'
import Alert from 'common/Alert.svelte'

let error: string|undefined = $state()
let tickets: Ticket[]|undefined = $state()

async function load () {
    tickets = await api.getTickets()
}

load().catch(async e => {
    error = await stringifyError(e)
})

async function deleteTicket (ticket: Ticket) {
    await api.deleteTicket(ticket)
    load()
}

</script>

{#if error}
<Alert color="danger">{error}</Alert>
{/if}

{#if tickets }
    <div class="page-summary-bar">
        {#if tickets.length }
            <h1>Access tickets: {tickets.length}</h1>
        {:else}
            <h1>No tickets created yet</h1>
        {/if}
        <a
            class="btn btn-outline-secondary ms-auto"
            href="/tickets/create"
            use:link>
            Create a ticket
        </a>
    </div>

    {#if tickets.length }
        <div class="list-group list-group-flush">
            {#each tickets as ticket}
                <div class="list-group-item">
                    <strong>
                        Access to {ticket.target} as {ticket.username}
                    </strong>
                    {#if ticket.expiry}
                        <small class="text-muted ms-4">
                            <Fa icon={ticket.expiry > new Date() ? faCalendarCheck : faCalendarXmark} fw /> Until {ticket.expiry?.toLocaleString()}
                        </small>
                    {/if}
                    {#if ticket.usesLeft != null}
                        {#if ticket.usesLeft > 0}
                            <small class="text-muted ms-4">
                                <Fa icon={faSquareCheck} fw /> Uses left: {ticket.usesLeft}
                            </small>
                        {/if}
                        {#if ticket.usesLeft === 0}
                            <small class="text-danger ms-4">
                                <Fa icon={faSquareXmark} fw /> Used up
                            </small>
                        {/if}
                    {/if}
                    <small class="text-muted me-4 ms-auto">
                        <RelativeDate date={ticket.created} />
                    </small>
                    <a href={''} onclick={e => {
                        deleteTicket(ticket)
                        e.preventDefault()
                    }}>Delete</a>
                </div>
            {/each}
        </div>
    {:else}
        <Alert color="info" fade={false}>
            Tickets are secret keys that allow access to one specific target without any additional authentication.
        </Alert>
    {/if}
{/if}


<style lang="scss">
    .list-group-item {
        display: flex;
        align-items: center;
    }
</style>
