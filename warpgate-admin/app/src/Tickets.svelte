<script lang="ts">
import { api, Ticket } from 'lib/api'
import { link } from 'svelte-spa-router'
import { Alert } from 'sveltestrap'
import RelativeDate from 'RelativeDate.svelte';

let error: Error|undefined
let tickets: Ticket[]|undefined

async function load () {
    tickets = await api.getTickets()
}

load().catch(e => {
    error = e
})

async function deleteTicket (ticket: Ticket) {
    await api.deleteTicket(ticket)
    load()
}

</script>

{#if error}
<Alert color="danger">{error.message}</Alert>
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
<div class="list-group list-group-flush">
    {#each tickets as ticket}
        <div class="list-group-item">
            <strong class="me-auto">
                Access to {ticket.target} as {ticket.username}
            </strong>
            <small class="text-muted me-4">
                <RelativeDate date={ticket.created} />
            </small>
            <a href={''} on:click|preventDefault={() => deleteTicket(ticket)}>Delete</a>
        </div>
    {/each}
</div>
{/if}


<style lang="scss">
    .list-group-item {
        display: flex;
        align-items: center;
    }
</style>
