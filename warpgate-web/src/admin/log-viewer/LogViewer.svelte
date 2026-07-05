<script lang="ts">
import { api, type GetLogsRequest, type LogEntry } from 'admin/lib/api'
import { firstBy } from 'thenby'
import IntersectionObserver from 'svelte-intersection-observer'
import { link } from 'svelte-spa-router'
import { onDestroy, onMount, untrack } from 'svelte'
import { createVirtualizer } from '@tanstack/svelte-virtual'
import { stringifyError } from 'common/errors'
import { Alert, Tooltip } from '@sveltestrap/sveltestrap'
import UserBadge from './UserBadge.svelte'
import AccessRoleBadge from './AccessRoleBadge.svelte'
import AdminRoleBadge from './AdminRoleBadge.svelte'
import TargetBadge from './TargetBadge.svelte'
import AsyncButton from 'common/AsyncButton.svelte'
import Fa from 'svelte-fa'
import { faDownload, faRotateRight } from '@fortawesome/free-solid-svg-icons'
import { downloadBlob } from 'common/helpers'

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
const EXPORT_PAGE_SIZE = 500

let error: string|null = $state(null)
let items: LogEntry[]|undefined
let visibleItems: LogEntry[]|undefined = $state()
let loading = $state(true)
let endReached = $state(false)
let loadOlderButton: HTMLButtonElement|undefined = $state()
let reloadInterval: ReturnType<typeof setInterval>
let searchQuery = $state('')
let scrollEl: HTMLDivElement|undefined = $state()

let virtualizerStore = createVirtualizer<HTMLDivElement, HTMLDivElement>({
    count: 0,
    getScrollElement: () => scrollEl ?? null,
    estimateSize: () => 48,
    overscan: 12,
})

let virtualItems = $derived($virtualizerStore.getVirtualItems())

async function getLogs(extra: Partial<GetLogsRequest> = {}) {
    const getLogsRequest: GetLogsRequest = {
        ...filters ?? {},
        search: searchQuery,
        ...extra,
    }

    return api.getLogs({ getLogsRequest })
}

function rowMeasure (node: HTMLDivElement) {
    $virtualizerStore.measureElement(node)
    return {
        destroy () {
            $virtualizerStore.measureElement(null)
        },
    }
}

$effect(() => {
    const list = visibleItems
    const count = list?.length ?? 0
    untrack(() => {
        $virtualizerStore.setOptions({
            count,
            getItemKey: (index) => String(list?.[index]?.id ?? index),
        })
    })
})

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
        const newItems = await getLogs({
            after: items?.at(0)?.timestamp,
            limit: PAGE_SIZE,
        })
        addItems(newItems)
        visibleItems = items
    } finally {
        loading = false
    }
}

async function loadOlder (searchMode = false) {
    if (endReached && !searchMode) {
        return
    }
    loading = true
    try {
        const newItems = await getLogs({
            before: searchMode ? undefined : items?.at(-1)?.timestamp,
            limit: PAGE_SIZE,
        })
        if (searchMode) {
            endReached = false
            items = []
        }

        const lengthBefore = items?.length ?? 0
        addItems(newItems)

        visibleItems = items
        if (lengthBefore === (items?.length ?? 0)) {
            // newItems.length is not necessarily 0 here
            // e.g. when fetching logs with "before" filter
            endReached = true
        }
    } finally {
        loading = false
    }
}

async function clearAndReload () {
    items = []
    visibleItems = []
    endReached = false
    try {
        await loadOlder(true)
    } catch (e) {
        error = await stringifyError(e)
    }
}

function search () {
    loadOlder(true)
}

function stringifyDate (date: Date) {
    return date.toLocaleString()
}

function filenameTimestamp () {
    return new Date().toISOString().replace(/[:.]/g, '-')
}

async function downloadLogs () {
    error = null

    const chunks: string[] = []
    let before: Date | undefined
    const baseRequest: Partial<GetLogsRequest> = {
        ...filters ?? {},
        search: searchQuery,
    }

    try {
        while (true) {
            const logs = await getLogs({
                ...baseRequest,
                before,
                limit: EXPORT_PAGE_SIZE,
            })
            if (!logs.length) {
                break
            }

            chunks.push(logs.map(log => JSON.stringify(log)).join('\n'))

            if (logs.length < EXPORT_PAGE_SIZE) {
                break
            }

            before = logs.at(-1)?.timestamp
        }

        downloadBlob(chunks.join('\n') + (chunks.length ? '\n' : ''), `warpgate-logs-${filenameTimestamp()}.ndjson`)
    } catch (e) {
        error = await stringifyError(e)
    }
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

interface UserAuthenticated1 {
    _type: 'UserAuthenticated1'
    user_id: string
    username: string
    credentials: string
    client_ip?: string
}

interface UserAuthenticationFailed1 {
    _type: 'UserAuthenticationFailed1'
    user_id?: string
    username: string
    credentials: string
    reason: string
    client_ip?: string
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

type RichLogEntry = AccessRoleGranted1 | AccessRoleRevoked1 | AdminRoleGranted1 | AdminRoleRevoked1 | UserCreated1 | UserDeleted1 | UserAuthenticated1 | UserAuthenticationFailed1 | TargetSessionStarted1 | TargetSessionEnded1 | CredentialCreated1 | CredentialDeleted1 | TicketCreated1 | TicketDeleted1

function richLogType(entry: LogEntry): string {
    return String(entry.values?._type ?? '').replace(/^"|"$/g, '')
}

function parseRichLogEntry(entry: LogEntry): RichLogEntry | null {
    const type = richLogType(entry)
    if (type === 'AccessRoleGranted1') {
        return entry.values as AccessRoleGranted1
    } else if (type === 'AccessRoleRevoked1') {
        return entry.values as AccessRoleRevoked1
    } else if (type === 'AdminRoleGranted1') {
        return entry.values as AdminRoleGranted1
    } else if (type === 'AdminRoleRevoked1') {
        return entry.values as AdminRoleRevoked1
    } else if (type === 'UserCreated1') {
        return entry.values as UserCreated1
    } else if (type === 'UserDeleted1') {
        return entry.values as UserDeleted1
    } else if (type === 'UserAuthenticated1') {
        return entry.values as UserAuthenticated1
    } else if (type === 'UserAuthenticationFailed1') {
        return entry.values as UserAuthenticationFailed1
    } else if (type === 'TargetSessionStarted1') {
        return entry.values as TargetSessionStarted1
    } else if (type === 'TargetSessionEnded1') {
        return entry.values as TargetSessionEnded1
    } else if (type === 'CredentialCreated1') {
        return entry.values as CredentialCreated1
    } else if (type === 'CredentialDeleted1') {
        return entry.values as CredentialDeleted1
    } else if (type === 'TicketCreated1') {
        return entry.values as TicketCreated1
    } else if (type === 'TicketDeleted1') {
        return entry.values as TicketDeleted1
    }
    return null
}

function genericValues(entry: LogEntry): [string, unknown][] {
    const pairs = Object.entries(entry.values ?? {})

    return pairs.filter(([key]) => ![
        '_type',
        'client_ip',
        'credentials',
        'reason',
        'user_id',
        'username',
    ].includes(key))
}
</script>

{#if error}
    <Alert color="danger">{error}</Alert>
{/if}

<div class="d-flex align-items-stretch gap-2 mb-2">
    <input
        placeholder="Search..."
        type="text"
        class="form-control form-control-sm flex-grow-1"
        style="min-width: 12rem"
        bind:value={searchQuery}
        onkeyup={() => search()} />
    <AsyncButton
    id = "clearAndReloadButton"
        color="link"
        click={clearAndReload}
        size="sm"
        disabled={loading}
    >
        <Fa icon={faRotateRight} fw />
    </AsyncButton>
    <Tooltip target="clearAndReloadButton" delay={500}>
        Clear view and reload latest log
    </Tooltip>
    <AsyncButton
        id="downloadLogsButton"
        color="link"
        click={downloadLogs}
        size="sm"
        disabled={loading && !visibleItems}
    >
        <Fa icon={faDownload} fw />
    </AsyncButton>
    <Tooltip target="downloadLogsButton" delay={500}>
        Download all matching logs
    </Tooltip>
</div>

{#if visibleItems}
    <div class="table-wrapper">
        <div
            class="log-scroll"
            bind:this={scrollEl}
        >
            <div
                class="virtual-inner"
                class:session-context={!!filters?.sessionId}
            >
                <div class="log-header">
                    <div class="timestamp">Time</div>
                    {#if !filters?.sessionId}
                        <div class="username">User</div>
                        <div class="session">Session</div>
                    {/if}
                    <div class="content">Event</div>
                </div>
                <div class="virtual-spacer" style="height: {virtualItems[0]?.start ?? 0}px"></div>
                {#each virtualItems as row (row.key)}
                    {@const item = visibleItems[row.index]}
                    {#if item}
                        {@const richEntry = parseRichLogEntry(item)}
                        <div
                            class="log-row"
                            data-index={row.index}
                            use:rowMeasure
                        >
                                <div class="timestamp">
                                    {stringifyDate(item.timestamp)}
                                </div>
                                {#if !filters?.sessionId}
                                    <div class="username">
                                        {#if item.username}
                                            {item.username}
                                        {/if}
                                    </div>
                                    <div class="session">
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
                                    {:else if richEntry?._type === 'UserAuthenticated1'}
                                    <div class="rich-entry">
                                        Authenticated
                                        <UserBadge id={richEntry.user_id} name={richEntry.username} />
                                        {#if richEntry.credentials}
                                            <span class="badge bg-secondary">{richEntry.credentials}</span>
                                        {/if}
                                        {#if richEntry.client_ip}
                                            <span class="text-muted">from {richEntry.client_ip}</span>
                                        {/if}
                                    </div>
                                    {:else if richEntry?._type === 'UserAuthenticationFailed1'}
                                    <div class="rich-entry auth-failed">
                                        <span class="event-label">Authentication failed</span>
                                        {#if richEntry.user_id}
                                            <UserBadge id={richEntry.user_id} name={richEntry.username} />
                                        {:else}
                                            <strong>{richEntry.username}</strong>
                                        {/if}
                                        {#if richEntry.credentials}
                                            <span class="badge bg-secondary">{richEntry.credentials}</span>
                                        {/if}
                                        {#if richEntry.reason}
                                            <span class="badge auth-failed-reason">{richEntry.reason}</span>
                                        {/if}
                                        {#if richEntry.client_ip}
                                            <span class="text-muted">from {richEntry.client_ip}</span>
                                        {/if}
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
                                        {#each genericValues(item) as pair (pair[0])}
                                        <span class="key-value">
                                            <span class="key">{pair[0]}:</span>
                                            <span class="value">{pair[1]}</span>
                                        </span>
                                        {/each}
                                    {/if}
                                </div>
                        </div>
                    {/if}
                {/each}
                <div class="virtual-spacer" style="height: {Math.max(0, $virtualizerStore.getTotalSize() - (virtualItems.at(-1)?.end ?? 0))}px"></div>
            </div>
            {#if !endReached}
                {#if !loading}
                    <div class="load-older-footer">
                        <IntersectionObserver element={loadOlderButton} on:observe={event => {
                            if (!loading && !error && event.detail.isIntersecting && !endReached) {
                                loadOlder()
                            }
                        }}>
                            <button
                                bind:this={loadOlderButton}
                                class="btn btn-secondary"
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
        flex: 1 0 0;
        min-height: 300px;
        max-width: 100%;
        overflow-x: auto;
        position: relative;
    }

    .log-scroll {
        position: absolute;
        left: 0;
        top: 0;
        width: 100%;
        height: 100%;
        overflow-y: auto;
        overflow-x: auto;
        contain: strict;
    }

    .virtual-inner {
        display: grid;
        grid-template-columns: min-content min-content min-content minmax(0, 1fr);
        column-gap: 1rem;
        min-width: 100%;

        &.session-context {
            grid-template-columns: min-content minmax(0, 1fr);
        }
    }

    .virtual-spacer {
        grid-column: 1 / -1;
    }

    .log-header {
        grid-column: 1 / -1;
        display: grid;
        grid-template-columns: subgrid;
        position: sticky;
        top: 0;
        z-index: 1;
        background: var(--bs-body-bg, #fff);
        font-family: $font-family-monospace;
        font-size: 0.75rem;
        font-weight: 600;
        padding: 0.25rem 0;
        border-bottom: 2px solid rgba(0, 0, 0, 0.12);
        white-space: nowrap;
    }

    .log-row {
        grid-column: 1 / -1;
        display: grid;
        grid-template-columns: subgrid;
        align-items: start;
        box-sizing: border-box;
        border-bottom: 1px solid rgba(0, 0, 0, 0.06);
        font-family: $font-family-monospace;
        font-size: 0.75rem;
        padding: 0.1rem 0;
        white-space: nowrap;

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

            .key-value {
                white-space: nowrap;

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
        }

        .rich-entry {
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            gap: 0.5em;

            .event-label {
                font-weight: 700;
            }

            &.auth-failed {
                .event-label {
                    color: var(--bs-danger-text-emphasis, #dc3545);
                }

                .auth-failed-reason {
                    background: rgba(var(--bs-danger-rgb, 220, 53, 69), 0.16);
                    border: 1px solid rgba(var(--bs-danger-rgb, 220, 53, 69), 0.34);
                    color: var(--bs-danger-text-emphasis, #dc3545);
                }
            }
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
