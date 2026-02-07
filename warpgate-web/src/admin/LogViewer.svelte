<script lang="ts">
import { api, type LogEntry } from 'admin/lib/api'
import { firstBy } from 'thenby'
import IntersectionObserver from 'svelte-intersection-observer'
import { link } from 'svelte-spa-router'
import { onDestroy, onMount } from 'svelte'
import { stringifyError } from 'common/errors'
import Alert from 'common/sveltestrap-s5-ports/Alert.svelte'

interface Props {
    filters: {
        sessionId?: string,
    } | undefined;
}

let { filters }: Props = $props()

let error: string|null = $state(null)
let items: LogEntry[]|undefined
let visibleItems: LogEntry[]|undefined = $state()
let loading = $state(true)
let endReached = $state(false)
let loadOlderButton: HTMLButtonElement|undefined = $state()
let reloadInterval: any
let searchQuery = $state('')
const PAGE_SIZE = 1000

function addItems (newItems: LogEntry[]) {
    let existingIds = new Set(items?.map(i => i.id) ?? [])
    newItems = newItems.filter(i => !existingIds.has(i.id))
    newItems.sort(firstBy('timestamp', -1))
    if (!newItems.length) {
        return
    }
    items ??= []
    if ((items?.[0]?.timestamp ?? 0) > newItems[0]!.timestamp) {
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
        visibleItems = items
    } finally {
        loading = false
    }
}

async function loadOlder (searchMode = false) {
    loading = true
    try {
        const newItems = await api.getLogs({
            getLogsRequest: {
                ...filters ?? {},
                before: searchMode ? undefined : items?.at(-1)?.timestamp,
                limit: PAGE_SIZE,
                search: searchQuery,
            },
        })
        if (searchMode) {
            endReached = false
            items = []
        }
        addItems(newItems)
        visibleItems = items
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

function formatBytes (bytes: number): string {
    if (bytes === 0) {
        return '0 B'
    }
    const k = 1024
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
}

loadOlder().catch(async e => {
    error = await stringifyError(e)
})

onMount(() => {
    reloadInterval = setInterval(() => {
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
    onkeyup={() => search()} />

{#if visibleItems}
    <div class="table-wrapper">
        <table class="w-100">
            <tbody>
                {#each visibleItems as item (item.id)}
                    <tr>
                        <td class="timestamp pe-4">
                            {stringifyDate(item.timestamp)}
                        </td>
                        {#if !filters?.sessionId}
                            <td class="username pe-4">
                                {#if item.username}
                                    {item.username}
                                {/if}
                            </td>
                            <td class="session pe-4">
                                {#if item.sessionId}
                                    <a href="/sessions/{item.sessionId}" use:link>
                                        {item.sessionId}
                                    </a>
                                {/if}
                            </td>
                        {/if}
                        <td class="content">
                            {#if item.values?.event_type === 'file_transfer'}
                                <span class="file-transfer-event {item.values.status}">
                                    <span class="badge {item.values.status === 'denied' ? 'badge-danger' : 'badge-info'}">
                                        {item.values.protocol?.toUpperCase() ?? 'FILE'}
                                    </span>
                                    <span class="direction">
                                        {item.values.direction?.toLowerCase() === 'upload' ? '\u2191' : '\u2193'}
                                    </span>
                                    <span class="path">{item.values.remote_path ?? ''}</span>
                                    {#if item.values.file_size}
                                        <span class="size">({formatBytes(item.values.file_size)})</span>
                                    {/if}
                                    {#if item.values.status === 'denied'}
                                        <span class="denied-reason">DENIED: {item.values.denied_reason ?? 'permission'}</span>
                                    {:else if item.values.status === 'completed'}
                                        <span class="completed">completed</span>
                                    {/if}
                                </span>
                            {:else}
                                <span class="text">
                                    {item.text}
                                </span>

                                {#each Object.entries(item.values ?? {}) as pair (pair[0])}
                                    <span class="key">{pair[0]}:</span>
                                    <span class="value">{pair[1]}</span>
                                {/each}
                            {/if}
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
                                        onclick={() => loadOlder()}
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
                        {#if !filters?.sessionId}
                            <td></td>
                            <td></td>
                        {/if}
                        <td class="text">End of the log</td>
                    </tr>
                {/if}
            </tbody>
        </table>
    </div>
{/if}

<style lang="scss">
    @import "../theme/vars.light";

    .table-wrapper {
        max-width: 100%;
        overflow-x: auto;
    }

    tr {
        td {
            font-family: $font-family-monospace;
            font-size: 0.75rem;
            white-space: nowrap;
        }

        .timestamp {
            opacity: .75;
        }

        td:not(:last-child) {
            padding-right: 1em;
        }

        .content {
            display: flex;

            .text {
                font-weight: bold;
                margin-right: 0.6em;
            }

            .key {
                margin-left: 0.5em;
                margin-right: 0.3em;
                opacity: .5;
                font-style: italic;
            }

            .value {
                font-style: italic;
            }

            .file-transfer-event {
                display: flex;
                align-items: center;
                gap: 0.5em;

                .badge {
                    font-size: 0.65rem;
                    padding: 0.2em 0.4em;
                    border-radius: 3px;
                    font-weight: 600;
                }

                .badge-info {
                    background-color: #17a2b8;
                    color: white;
                }

                .badge-danger {
                    background-color: #dc3545;
                    color: white;
                }

                .direction {
                    font-weight: bold;
                    font-size: 1.1em;
                }

                .path {
                    font-weight: 500;
                }

                .size {
                    opacity: 0.7;
                    font-size: 0.9em;
                }

                .denied-reason {
                    color: #dc3545;
                    font-weight: 600;
                }

                .completed {
                    color: #28a745;
                    font-size: 0.85em;
                }

                &.denied {
                    .path {
                        text-decoration: line-through;
                        opacity: 0.7;
                    }
                }
            }
        }
    }
</style>
