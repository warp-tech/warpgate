<script lang="ts">
import { api, TicketSnapshot } from 'lib/api'
import { link } from 'svelte-spa-router'
import { Alert, Spinner } from 'sveltestrap'

let error: Error|undefined
let tickets: TicketSnapshot[]|undefined

async function load () {
    tickets = await api.getTickets()
}

load().catch(e => {
    error = e
})

async function deleteTicket (ticket: TicketSnapshot) {

}

</script>

{#if error}
<Alert color="danger">{error.message}</Alert>
{/if}

<a
    class="btn btn-primary"
    href="/tickets/create"
    use:link
>Create</a>

{#if tickets }
<div class="list-group list-group-flush">
    {#each tickets as ticket}
        <div class="list-group-item">
            <div class="main">
                <strong>
                    {ticket.id}
                </strong>

                <code>{ticket.username}</code>
                <code>{ticket.target}</code>
                <button on:click="{() => deleteTicket(ticket)}">Delete</button>
            </div>
        </div>
    {/each}
</div>
{/if}
