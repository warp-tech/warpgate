<script lang="ts">
import { api, type GetLogsRequest, type LogEntry } from 'admin/lib/api'
import { firstBy } from 'thenby'
import IntersectionObserver from 'svelte-intersection-observer'
import { link } from 'svelte-spa-router'
import { onDestroy, onMount } from 'svelte'
import { get } from 'svelte/store'
import { createVirtualizer, measureElement } from '@tanstack/svelte-virtual'
import { stringifyError } from 'common/errors'
import Alert from 'common/sveltestrap-s5-ports/Alert.svelte'

import UserBadge from './UserBadge.svelte'
import AccessRoleBadge from './AccessRoleBadge.svelte'
import AdminRoleBadge from './AdminRoleBadge.svelte'
import TargetBadge from './TargetBadge.svelte'

interface Props {
    filters?: {
        sessionId?: string,
        target?: string,
        relatedUsers?: string,
        relatedAccessRoles?: string,
        relatedAdminRoles?: string,
    }
}

let { filters }: Props = $props()

/** Cap in-memory log rows (see github.com/warp-tech/warpgate/issues/1836). */
const MAX_LOGS = 500
const POLL_INTERVAL_MS = 3000
const PAGE_SIZE = 500

let error: string|null = $state(null)
let items: LogEntry[]|undefined
let visibleItems: LogEntry[]|undefined = $state()
let loading = $state(true)
let endReached = $state(false)
let loadOlderButton: HTMLButtonElement|undefined = $state()
let reloadInterval: ReturnType<typeof setInterval>
let searchQuery = $state('')
let scrollEl: HTMLDivElement|undefined = $state()

const virtualizerStore = createVirtualizer<HTMLDivElement, HTMLDivElement>({
    count: 0,
    getScrollElement: () => scrollEl ?? null,
    estimateSize: () => 48,
    overscan: 12,
    measureElement,
})

$effect(() => {
    const list = visibleItems
    const count = list?.length ?? 0
    get(virtualizerStore).setOptions({
        count,
        getItemKey: (index) => String(list?.[index]?.id ?? index),
    })
})

function rowMeasure (node: HTMLDivElement) {
    get(virtualizerStore).measureElement(node)
    return {
        destroy () {
            get(virtualizerStore).measureElement(null)
        },
    }
}

function addItems (newItems: LogEntry[]) {
    const existingIds = new Set(items?.map(i => i.id) ?? [])
    newItems = newItems.filter(i => !existingIds.has(i.id))
    newItems.sort(firstBy('timestamp', -1))
    if (!newItems.length) {
        return
    }
    items ??= []
    const prepended = !((items?.[0]?.timestamp ?? 0) > newItems[0]!.timestamp)
    if (!prepended) {
        items = items.concat(newItems)
    } else {
        items = [
            ...newItems,
            ...items,
        ]
    }
    if (items.length > MAX_LOGS) {
        items = prepended
            ? items.slice(0, MAX_LOGS)
            : items.slice(-MAX_LOGS)
    }
}

async function loadNewer () {
    loading = true
    try {
        const getLogsRequest: GetLogsRequest = {
            ...filters ?? {},
            after: items?.at(0)?.timestamp,
            limit: PAGE_SIZE,
            search: searchQuery,
        }

        const newItems = await api.getLogs({ getLogsRequest })
        addItems(newItems)
        visibleItems = items
    } finally {
        loading = false
    }
}

async function loadOlder (searchMode = false) {
    loading = true
    try {
        const getLogsRequest: GetLogsRequest = {
            ...filters ?? {},
            before: searchMode ? undefined : items?.at(-1)?.timestamp,
            limit: PAGE_SIZE,
            search: searchQuery,
        }

        const newItems = await api.getLogs({ getLogsRequest })
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

function clearUiLogs () {
    items = []
    visibleItems = []
    endReached = false
    loadOlder(true).catch(async e => {
        error = await stringifyError(e)
    })
}

function search () {
    loadOlder(true)
}

function stringifyDate (date: Date) {
    return date.toLocaleString()
}

loadOlder().catch(async e => {
    error = await stringifyError(e)
})

onMount(() => {
    reloadInterval = setInterval(() => {
        if (!loading) {
            loadNewer()
        }
    }, POLL_INTERVAL_MS)
})

onDestroy(() => {
    clearInterval(reloadInterval)
})

interface AccessRoleGranted1 {
    _type: 'AccessRoleGranted1'
    grantee_id: string
    grantee_username: string
    role_id: string
    role_name: string
}

interface AccessRoleRevoked1 {
    _type: 'AccessRoleRevoked1'
    grantee_id: string
    grantee_username: string
    role_id: string
    role_name: string
}

interface AdminRoleGranted1 {
    _type: 'AdminRoleGranted1'
    grantee_id: string
    grantee_username: string
    admin_role_id: string
    admin_role_name: string
}

interface AdminRoleRevoked1 {
    _type: 'AdminRoleRevoked1'
    grantee_id: string
    grantee_username: string
    admin_role_id: string
    admin_role_name: string
}

interface UserCreated1 {
    _type: 'UserCreated1'
    user_id: string
    username: string
}

interface UserDeleted1 {
    _type: 'UserDeleted1'
    user_id: string
    username: string
}

interface CredentialCreated1 {
    _type: 'CredentialCreated1'
    credential_type: string
    credential_name?: string
    via: 'admin' | 'self-service'
    user_id: string
    username: string
}

interface CredentialDeleted1 {
    _type: 'CredentialDeleted1'
    credential_type: string
    credential_name?: string
    via: 'admin' | 'self-service'
    user_id: string
    username: string
}

interface TargetSessionStarted1 {
    _type: 'TargetSessionStarted1'
    session_id: string
    target_id: string
    target_name: string
    user_id: string
    username: string
}

interface TargetSessionEnded1 {
    _type: 'TargetSessionEnded1'
    session_id: string
    target_id: string
    target_name: string
    user_id: string
    username: string
}

interface TicketCreated1 {
    _type: 'TicketCreated1'
    ticket_id: string
    username: string
    target: string
}

interface TicketDeleted1 {
    _type: 'TicketDeleted1'
    ticket_id: string
    username: string
    target: string
}

type RichLogEntry = AccessRoleGranted1 | AccessRoleRevoked1 | AdminRoleGranted1 | AdminRoleRevoked1 | UserCreated1 | UserDeleted1 | TargetSessionStarted1 | TargetSessionEnded1 | CredentialCreated1 | CredentialDeleted1 | TicketCreated1 | TicketDeleted1

function parseRichLogEntry(entry: LogEntry): RichLogEntry | null {
    if (entry.values._type === 'AccessRoleGranted1') {
        return entry.values as AccessRoleGranted1
    } else if (entry.values._type === 'AccessRoleRevoked1') {
        return entry.values as AccessRoleRevoked1
    } else if (entry.values._type === 'AdminRoleGranted1') {
        return entry.values as AdminRoleGranted1
    } else if (entry.values._type === 'AdminRoleRevoked1') {
        return entry.values as AdminRoleRevoked1
    } else if (entry.values._type === 'UserCreated1') {
        return entry.values as UserCreated1
    } else if (entry.values._type === 'UserDeleted1') {
        return entry.values as UserDeleted1
    } else if (entry.values._type === 'TargetSessionStarted1') {
        return entry.values as TargetSessionStarted1
    } else if (entry.values._type === 'TargetSessionEnded1') {
        return entry.values as TargetSessionEnded1
    } else if (entry.values._type === 'CredentialCreated1') {
        return entry.values as CredentialCreated1
    } else if (entry.values._type === 'CredentialDeleted1') {
        return entry.values as CredentialDeleted1
    } else if (entry.values._type === 'TicketCreated1') {
        return entry.values as TicketCreated1
    } else if (entry.values._type === 'TicketDeleted1') {
        return entry.values as TicketDeleted1
    }
    return null
}
</script>

{#if error}
    <Alert color="danger">{error}</Alert>
{/if}

<div class="d-flex flex-wrap align-items-center gap-2 mb-2">
    <input
        placeholder="Search..."
        type="text"
        class="form-control form-control-sm flex-grow-1"
        style="min-width: 12rem"
        bind:value={searchQuery}
        onkeyup={() => search()} />
    <button
        type="button"
        class="btn btn-sm btn-outline-secondary"
        onclick={() => clearUiLogs()}
        disabled={loading}
        title="Clear on-screen logs and reload the latest page from the server (does not delete stored logs)"
    >
        Clear UI logs
    </button>
</div>

{#if visibleItems}
    <div class="table-wrapper">
        <div
            class="log-scroll"
            bind:this={scrollEl}
        >
            <div
                class="virtual-inner"
                style="height: {$virtualizerStore.getTotalSize()}px"
            >
                {#each $virtualizerStore.getVirtualItems() as row (row.key)}
                    {@const item = visibleItems[row.index]}
                    {#if item}
                        {@const richEntry = parseRichLogEntry(item)}
                        <div
                            class="log-row"
                            style="transform: translateY({row.start}px)"
                            use:rowMeasure
                        >
                            <div
                                class="log-row-grid"
                                class:session-context={!!filters?.sessionId}
                            >
                                <div class="timestamp pe-4">
                                    {stringifyDate(item.timestamp)}
                                </div>
                                {#if !filters?.sessionId}
                                    <div class="username pe-4">
                                        {#if item.username}
                                            {item.username}
                                        {/if}
                                    </div>
                                    <div class="session pe-4">
                                        {#if item.sessionId}
                                            <a href="/sessions/{item.sessionId}" use:link>
                                                {item.sessionId}
                                            </a>
                                        {/if}
                                    </div>
                                {/if}
                                <div class="content">
                                    {#if richEntry?._type === 'AccessRoleGranted1'}
                                    <div class="rich-entry">
                                        Granted
                                        <AccessRoleBadge id={richEntry.role_id} name={richEntry.role_name} />
                                        access role to
                                        <UserBadge id={richEntry.grantee_id} name={richEntry.grantee_username} />
                                    </div>
                                    {:else if richEntry?._type === 'AccessRoleRevoked1'}
                                    <div class="rich-entry">
                                        Revoked
                                        <AccessRoleBadge id={richEntry.role_id} name={richEntry.role_name} />
                                        access role from
                                        <UserBadge id={richEntry.grantee_id} name={richEntry.grantee_username} />
                                    </div>
                                    {:else if richEntry?._type === 'AdminRoleGranted1'}
                                    <div class="rich-entry">
                                        Granted
                                        <AdminRoleBadge id={richEntry.admin_role_id} name={richEntry.admin_role_name} />
                                        admin role to
                                        <UserBadge id={richEntry.grantee_id} name={richEntry.grantee_username} />
                                    </div>
                                    {:else if richEntry?._type === 'AdminRoleRevoked1'}
                                    <div class="rich-entry">
                                        Revoked
                                        <AdminRoleBadge id={richEntry.admin_role_id} name={richEntry.admin_role_name} />
                                        admin role from
                                        <UserBadge id={richEntry.grantee_id} name={richEntry.grantee_username} />
                                    </div>
                                    {:else if richEntry?._type === 'UserCreated1'}
                                    <div class="rich-entry">
                                        Created user
                                        <UserBadge id={richEntry.user_id} name={richEntry.username} />
                                    </div>
                                    {:else if richEntry?._type === 'UserDeleted1'}
                                    <div class="rich-entry">
                                        Deleted user
                                        <UserBadge id={richEntry.user_id} name={richEntry.username} />
                                    </div>
                                    {:else if richEntry?._type === 'TargetSessionStarted1'}
                                    <div class="rich-entry">
                                        Target session started for
                                        <UserBadge id={richEntry.user_id} name={richEntry.username} />
                                        on target
                                        <TargetBadge id={richEntry.target_id} name={richEntry.target_name} />
                                    </div>
                                    {:else if richEntry?._type === 'TargetSessionEnded1'}
                                    <div class="rich-entry">
                                        Target session ended for
                                        <UserBadge id={richEntry.user_id} name={richEntry.username} />
                                        on target
                                        <TargetBadge id={richEntry.target_id} name={richEntry.target_name} />
                                    </div>
                                    {:else if richEntry?._type === 'CredentialCreated1'}
                                    <div class="rich-entry">
                                        Added {richEntry.credential_type} credential
                                        {#if richEntry.credential_name}
                                            <strong>{richEntry.credential_name}</strong>
                                        {/if}
                                        for
                                        <UserBadge id={richEntry.user_id} name={richEntry.username} />
                                        {#if richEntry.via === 'self-service'}
                                            <span class="badge bg-secondary">self-service</span>
                                        {/if}
                                    </div>
                                    {:else if richEntry?._type === 'CredentialDeleted1'}
                                    <div class="rich-entry">
                                        Removed {richEntry.credential_type} credential
                                        {#if richEntry.credential_name}
                                            <strong>{richEntry.credential_name}</strong>
                                        {/if}
                                        from
                                        <UserBadge id={richEntry.user_id} name={richEntry.username} />
                                        {#if richEntry.via === 'self-service'}
                                            <span class="badge bg-secondary">self-service</span>
                                        {/if}
                                    </div>
                                    {:else if richEntry?._type === 'TicketCreated1'}
                                    <div class="rich-entry">
                                        Created ticket for
                                        <strong>{richEntry.username}</strong>
                                        to target
                                        <strong>{richEntry.target}</strong>
                                    </div>
                                    {:else if richEntry?._type === 'TicketDeleted1'}
                                    <div class="rich-entry">
                                        Deleted ticket for
                                        <strong>{richEntry.username}</strong>
                                        targeting
                                        <strong>{richEntry.target}</strong>
                                    </div>
                                    {:else}
                                        <span class="text">
                                            {item.text}
                                        </span>
                                        {#each Object.entries(item.values ?? {}) as pair (pair[0])}
                                            <span class="key">{pair[0]}:</span>
                                            <span class="value">{pair[1]}</span>
                                        {/each}
                                    {/if}
                                </div>
                            </div>
                        </div>
                    {/if}
                {/each}
            </div>
            {#if !endReached}
                {#if !loading}
                    <div class="load-older-footer">
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
                    </div>
                {/if}
            {:else}
                <div class="end-of-log text-muted small py-2">End of the log</div>
            {/if}
        </div>
    </div>
{/if}

<style lang="scss">
    @import "../../theme/vars.light";

    .table-wrapper {
        max-width: 100%;
        overflow-x: auto;
    }

    .log-scroll {
        max-height: min(70vh, 56rem);
        overflow-y: auto;
        overflow-x: auto;
        contain: strict;
    }

    .virtual-inner {
        position: relative;
        width: 100%;
    }

    .log-row {
        position: absolute;
        top: 0;
        left: 0;
        width: 100%;
        box-sizing: border-box;
        border-bottom: 1px solid rgba(0, 0, 0, 0.06);
    }

    .log-row-grid {
        display: grid;
        grid-template-columns: min-content min-content min-content minmax(0, 1fr);
        align-items: start;
        gap: 0 1rem;
        font-family: $font-family-monospace;
        font-size: 0.75rem;
        padding: 0.35rem 0;
        white-space: nowrap;

        &.session-context {
            grid-template-columns: min-content minmax(0, 1fr);
        }

        .timestamp {
            opacity: .75;
        }

        .content {
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            min-width: 0;
            white-space: normal;

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
        }

        .rich-entry {
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            gap: 0.5em;
        }
    }

    .load-older-footer {
        padding: 0.75rem 0;
    }

    .end-of-log {
        font-family: $font-family-monospace;
        font-size: 0.75rem;
    }

</style>
