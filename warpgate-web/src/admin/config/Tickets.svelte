<script lang="ts">
    import { api, type Ticket } from 'admin/lib/api'
    import { link } from 'svelte-spa-router'
    import RelativeDate from '../RelativeDate.svelte'
    import Fa from 'svelte-fa'
    import { faCalendarXmark, faCalendarCheck, faSquareXmark, faSquareCheck } from '@fortawesome/free-solid-svg-icons'
    import { stringifyError } from 'common/errors'
    import Alert from 'common/sveltestrap-s5-ports/Alert.svelte'
    import EmptyState from 'common/EmptyState.svelte'
    import { Button } from '@sveltestrap/sveltestrap'

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

<div class="container-max-lg">
    {#if error}
    <Alert color="danger">{error}</Alert>
    {/if}

    {#if tickets}
        <div class="page-summary-bar">
            {#if tickets.length }
                <h1>access tickets: <span class="counter">{tickets.length}</span></h1>
            {:else}
                <h1>access tickets</h1>
            {/if}
            <a
                class="btn btn-primary ms-auto"
                href="/config/tickets/create"
                use:link>
                Create a ticket
            </a>
        </div>

        {#if tickets.length}
            <div class="list-group list-group-flush">
                {#each tickets as ticket (ticket.id)}
                    <div class="list-group-item">
                        <div>
                            <strong>
                                Access to {ticket.target} as {ticket.username}
                            </strong>
                            {#if ticket.description}
                                <small class="d-block text-muted">
                                    {ticket.description}
                                </small>
                            {/if}
                        </div>
                        {#if ticket.expiry}
                            <small class="text-muted ms-4 d-flex align-items-center">
                                <Fa icon={ticket.expiry > new Date() ? faCalendarCheck : faCalendarXmark} fw /> Until {ticket.expiry?.toLocaleString()}
                            </small>
                        {/if}
                        {#if ticket.usesLeft != null}
                            {#if ticket.usesLeft > 0}
                                <small class="text-muted ms-4 d-flex align-items-center">
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
                        <Button color="link" onclick={e => {
                            deleteTicket(ticket)
                            e.preventDefault()
                        }}>Delete</Button>
                    </div>
                {/each}
            </div>
        {:else}
            <EmptyState
                title="No tickets yet"
                hint="Tickets are secret keys that allow access to one specific target without any additional authentication"
            />
        {/if}
    {/if}
</div>

<style lang="scss">
    .list-group-item {
        display: flex;
        align-items: center;
    }
</style>
