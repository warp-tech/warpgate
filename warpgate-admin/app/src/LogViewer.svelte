<script lang="ts">
import { api, LogEntry } from 'lib/api'
import { Alert, FormGroup } from 'sveltestrap'
import { firstBy } from 'thenby';
import IntersectionObserver from 'svelte-intersection-observer'
import { onDestroy, onMount } from 'svelte'

export let filters: {
    sessionId?: string,
} | undefined

let error: Error|undefined
let items: LogEntry[]|undefined
let loading = true
let endReached = false
let loadOlderButton: HTMLButtonElement|undefined
let reloadInterval: number|undefined
let lastUpdate = new Date()
let isLive = true
let searchQuery = ''
const PAGE_SIZE = 10

function addItems (newItems: LogEntry[]) {
    lastUpdate = new Date()
    let existingIds = new Set(items?.map(i => i.id) ?? [])
    newItems = newItems.filter(i => !existingIds.has(i.id))
    newItems.sort(firstBy('timestamp', -1))
    if (!newItems.length) {
        return
    }
    items ??= []
    if (items?.[0]?.timestamp > newItems[0].timestamp) {
        items = items.concat(newItems)
    } else {
        items = [
            ...newItems,
            ...items,
        ]
    }
}

async function loadNewer () {
    loading = true
    try {
        const newItems = await api.getLogs({
            getLogsRequest: {
                ...filters ?? {},
                after: items?.at(0)?.timestamp,
                limit: PAGE_SIZE,
                search: searchQuery,
            },
        })
        addItems(newItems)
    } finally {
        loading = false
    }
}

async function loadOlder (replace = false) {
    loading = true
    try {
        const newItems = await api.getLogs({
            getLogsRequest: {
                ...filters ?? {},
                before: items?.at(-1)?.timestamp,
                limit: PAGE_SIZE,
                search: searchQuery,
            },
        })
        if (replace) {
            items = undefined
            endReached = false
        }
        addItems(newItems)
        if (!newItems.length) {
            endReached = true
        }
    } finally {
        loading = false
    }
}

function search () {
    loadOlder(true)
}

function stringifyDate (date: Date) {
    return date.toLocaleString()
}

loadOlder().catch(e => {
    error = e
})

onMount(() => {
    reloadInterval = setInterval(() => {
        isLive = Date.now() - lastUpdate.valueOf() < 3000
        if (!loading) {
            loadNewer()
        }
    }, 1000)
})

onDestroy(() => {
    clearInterval(reloadInterval)
})


</script>

{#if error}
    <Alert color="danger">{error}</Alert>
{/if}

<input
    placeholder="Search..."
    type="text"
    class="form-control form-control-sm mb-2"
    bind:value={searchQuery}
    on:keyup={() => search()} />

{#if items }
    <table class="w-100">
        <tr>
            <th>Time</th>
            <th>User</th>
            <th class="d-flex">
                <div class="me-auto">Message</div>
                {#if isLive}
                    <span class="badge bg-danger">Live</span>
                {:else}
                    <small><em>Last update: {stringifyDate(lastUpdate)}</em></small>
                {/if}
            </th>
        </tr>
        {#each items as item}
            <tr>
                <td class="timestamp pe-4">
                    {stringifyDate(item.timestamp)}
                </td>
                <td class="username pe-4">
                    {#if item.username}
                        {item.username}
                    {/if}
                </td>
                <td class="text">
                    {item.text}
                </td>
            </tr>
            {/each}
            {#if !endReached}
                {#if !loading}
                    <tr>
                        <td colspan="3">
                            <IntersectionObserver element={loadOlderButton} on:observe={event => {
                                if (!loading && event.detail.isIntersecting) {
                                    loadOlder()
                                }
                            }}>
                                <button
                                    bind:this={loadOlderButton}
                                    class="btn btn-light"
                                    on:click={() => loadOlder()}
                                    disabled={loading}
                                >
                                    Load older
                                </button>
                            </IntersectionObserver>
                        </td>
                    </tr>
                {/if}
            {:else}
                <tr>
                    <td></td>
                    <td></td>
                    <td class="text">End of the log</td>
                </tr>
            {/if}
    </table>
{/if}


<style lang="scss">
    @import "./vars";

    tr {
        td {
            font-family: $font-family-monospace;
            font-size: 0.75rem;
        }

        .timestamp {
            opacity: .75;
        }

        :not(:last-child) {
            padding-right: 15px;
        }
    }

    .badge {
        line-height: 1.3;
    }
</style>
