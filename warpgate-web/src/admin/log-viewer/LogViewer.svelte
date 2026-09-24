<script lang="ts">
    import {
        faDownload,
        faRotateRight,
    } from '@fortawesome/free-solid-svg-icons'
    import { createVirtualizer } from '@tanstack/svelte-virtual'
    import { api, type GetLogsRequest, type LogEntry } from 'admin/lib/api'
    import { stringifyError } from 'common/errors'
    import { downloadBlob } from 'common/helpers'
    import { onDestroy, onMount, untrack } from 'svelte'
    import IntersectionObserver from 'svelte-intersection-observer'
    import { link } from 'svelte-spa-router'
    import { firstBy } from 'thenby'
    import Button from 'ui/Button.svelte'
    import Callout from 'ui/Callout.svelte'
    import Input from 'ui/Input.svelte'
    import Tooltip from 'ui/Tooltip.svelte'
    import AccessRoleBadge from './AccessRoleBadge.svelte'
    import AdminRoleBadge from './AdminRoleBadge.svelte'
    import TargetBadge from './TargetBadge.svelte'
    import UserBadge from './UserBadge.svelte'

    interface Props {
        filters?: {
            sessionId?: string
            target?: string
            relatedUsers?: string
            relatedAccessRoles?: string
            relatedAdminRoles?: string
        }
    }

    let { filters }: Props = $props()

    /** Cap in-memory log rows (see github.com/warp-tech/warpgate/issues/1836). */
    const MAX_LOGS = 500
    const POLL_INTERVAL_MS = 3000
    const PAGE_SIZE = 500
    const EXPORT_PAGE_SIZE = 500

    let error: string | null = $state(null)
    let items: LogEntry[] | undefined
    let visibleItems: LogEntry[] | undefined = $state()
    let loading = $state(true)
    let endReached = $state(false)
    let loadOlderButton: HTMLButtonElement | undefined = $state()
    let reloadInterval: ReturnType<typeof setInterval>
    let searchQuery = $state('')
    let scrollEl: HTMLDivElement | undefined = $state()

    let virtualizerStore = createVirtualizer<HTMLDivElement, HTMLDivElement>({
        count: 0,
        getScrollElement: () => scrollEl ?? null,
        estimateSize: () => 48,
        overscan: 12,
    })

    let virtualItems = $derived($virtualizerStore.getVirtualItems())

    async function getLogs(extra: Partial<GetLogsRequest> = {}) {
        const getLogsRequest: GetLogsRequest = {
            ...(filters ?? {}),
            search: searchQuery,
            ...extra,
        }

        return api.getLogs({ getLogsRequest })
    }

    function rowMeasure(node: HTMLDivElement) {
        $virtualizerStore.measureElement(node)
        return {
            destroy() {
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
                getItemKey: index => String(list?.[index]?.id ?? index),
            })
        })
    })

    function addItems(newItems: LogEntry[]) {
        const existingIds = new Set(items?.map(i => i.id) ?? [])
        newItems = newItems.filter(i => !existingIds.has(i.id))
        newItems.sort(firstBy('timestamp', -1))
        if (!newItems.length) {
            return
        }
        items ??= []
        // biome-ignore lint/style/noNonNullAssertion: newItems is non-empty (guarded above)
        const firstNewTimestamp = newItems[0]!.timestamp
        const prepended = !((items?.[0]?.timestamp ?? 0) > firstNewTimestamp)
        if (!prepended) {
            items = items.concat(newItems)
        } else {
            items = [...newItems, ...items]
        }
        if (items.length > MAX_LOGS) {
            items = prepended
                ? items.slice(0, MAX_LOGS)
                : items.slice(-MAX_LOGS)
        }
    }

    async function loadNewer() {
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

    async function loadOlder(searchMode = false) {
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

    async function clearAndReload() {
        items = []
        visibleItems = []
        endReached = false
        try {
            await loadOlder(true)
        } catch (e) {
            error = await stringifyError(e)
        }
    }

    function search() {
        loadOlder(true)
    }

    function stringifyDate(date: Date) {
        return date.toLocaleString()
    }

    function filenameTimestamp() {
        return new Date().toISOString().replace(/[:.]/g, '-')
    }

    async function downloadLogs() {
        error = null

        const chunks: string[] = []
        let before: Date | undefined
        const baseRequest: Partial<GetLogsRequest> = {
            ...(filters ?? {}),
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

            downloadBlob(
                chunks.join('\n') + (chunks.length ? '\n' : ''),
                `warpgate-logs-${filenameTimestamp()}.ndjson`,
            )
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

    interface WebApprovalBypassed1 {
        _type: 'WebApprovalBypassed1'
        session: string
        client_ip: string
        user_id: string
        username: string
        protocol: string
        target: string
    }

    /** Identity every Kubernetes audit event carries. */
    interface KubernetesEvent {
        user_id: string
        username: string
        target_id: string
        target_name: string
        namespace: string
        pod: string
    }

    interface KubernetesExecStarted1 extends KubernetesEvent {
        _type: 'KubernetesExecStarted1'
        container?: string
        /** argv, stored as a JSON array in a single field. */
        command: string
        tty: string
        stdin: string
    }

    interface KubernetesAttachStarted1 extends KubernetesEvent {
        _type: 'KubernetesAttachStarted1'
        container?: string
        tty: string
    }

    interface KubernetesPortForwardStarted1 extends KubernetesEvent {
        _type: 'KubernetesPortForwardStarted1'
        /** Absent when the client negotiated ports per stream instead. */
        ports?: string
    }

    interface KubernetesStreamRejected1 extends KubernetesEvent {
        _type: 'KubernetesStreamRejected1'
        subresource: string
        status: string
    }

    interface KubernetesDebugContainerCreated1 extends KubernetesEvent {
        _type: 'KubernetesDebugContainerCreated1'
        debug_container: string
        image: string
        target_container?: string
        command: string
        tty: string
        response_status: string
    }

    interface KubernetesPodCreated1 extends KubernetesEvent {
        _type: 'KubernetesPodCreated1'
        images: string
        node_name?: string
        host_pid: string
        host_network: string
        privileged: string
        response_status: string
    }

    type RichLogEntry =
        | AccessRoleGranted1
        | AccessRoleRevoked1
        | AdminRoleGranted1
        | AdminRoleRevoked1
        | UserCreated1
        | UserDeleted1
        | UserAuthenticated1
        | UserAuthenticationFailed1
        | TargetSessionStarted1
        | TargetSessionEnded1
        | CredentialCreated1
        | CredentialDeleted1
        | TicketCreated1
        | TicketDeleted1
        | WebApprovalBypassed1
        | KubernetesExecStarted1
        | KubernetesAttachStarted1
        | KubernetesPortForwardStarted1
        | KubernetesStreamRejected1
        | KubernetesDebugContainerCreated1
        | KubernetesPodCreated1

    function richLogType(entry: LogEntry): string {
        return String(entry.values?._type ?? '').replace(/^"|"$/g, '')
    }

    const richLogTypes: ReadonlySet<string> = new Set<RichLogEntry['_type']>([
        'AccessRoleGranted1',
        'AccessRoleRevoked1',
        'AdminRoleGranted1',
        'AdminRoleRevoked1',
        'UserCreated1',
        'UserDeleted1',
        'UserAuthenticated1',
        'UserAuthenticationFailed1',
        'TargetSessionStarted1',
        'TargetSessionEnded1',
        'CredentialCreated1',
        'CredentialDeleted1',
        'TicketCreated1',
        'TicketDeleted1',
        'KubernetesExecStarted1',
        'KubernetesAttachStarted1',
        'KubernetesPortForwardStarted1',
        'KubernetesStreamRejected1',
        'KubernetesDebugContainerCreated1',
        'KubernetesPodCreated1',
    ])

    function parseRichLogEntry(entry: LogEntry): RichLogEntry | null {
        return richLogTypes.has(richLogType(entry))
            ? (entry.values as RichLogEntry)
            : null
    }

    /**
     * Kubernetes audit events pack argv, ports and image lists into one field
     * as a JSON array, so a log row stays a flat set of values.
     */
    function formatJsonList(
        raw: string | undefined,
        separator: string,
    ): string {
        if (!raw) {
            return ''
        }
        try {
            const parsed: unknown = JSON.parse(raw)
            return Array.isArray(parsed) ? parsed.join(separator) : raw
        } catch {
            return raw
        }
    }

    function genericValues(entry: LogEntry): [string, unknown][] {
        const pairs = Object.entries(entry.values ?? {})

        return pairs.filter(
            ([key]) =>
                ![
                    '_type',
                    'client_ip',
                    'credentials',
                    'reason',
                    'user_id',
                    'username',
                ].includes(key),
        )
    }
</script>

{#if error}
    <Callout tone="danger" title="Could not load the log">{error}</Callout>
{/if}

<div class="log-toolbar">
    <div class="log-search">
        <Input
            label="Search the log"
            labelHidden
            type="search"
            size="compact"
            placeholder="Search…"
            bind:value={searchQuery}
            onkeyup={() => search()}
        />
    </div>

    <!--
      ui/Tooltip wraps its trigger rather than targeting one by id, so the
      icon-only buttons sit inside it. Each still carries its own `label`,
      which is the accessible name — the tooltip is the visible hint, not the
      name, and a tooltip alone would leave these two buttons unnamed.
    -->
    <Tooltip text="Clear view and reload latest log" delay={500}>
        <Button
            variant="ghost"
            size="compact"
            label="Clear view and reload latest log"
            disabled={loading}
            click={clearAndReload}
        >
            <svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true">
                <path
                    d="M13.5 8a5.5 5.5 0 1 1-1.6-3.9"
                    fill="none"
                    stroke="currentColor"
                    stroke-width="1.5"
                    stroke-linecap="round"
                />
                <path
                    d="M13.5 2v3h-3"
                    fill="none"
                    stroke="currentColor"
                    stroke-width="1.5"
                    stroke-linecap="round"
                    stroke-linejoin="round"
                />
            </svg>
        </Button>
    </Tooltip>

    <Tooltip text="Download all matching logs" delay={500}>
        <Button
            variant="ghost"
            size="compact"
            label="Download all matching logs"
            disabled={loading && !visibleItems}
            click={downloadLogs}
        >
            <svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true">
                <path
                    d="M8 2v8"
                    stroke="currentColor"
                    stroke-width="1.5"
                    stroke-linecap="round"
                />
                <path
                    d="M4.75 6.75L8 10l3.25-3.25"
                    fill="none"
                    stroke="currentColor"
                    stroke-width="1.5"
                    stroke-linecap="round"
                    stroke-linejoin="round"
                />
                <path
                    d="M2.75 12.5h10.5"
                    stroke="currentColor"
                    stroke-width="1.5"
                    stroke-linecap="round"
                />
            </svg>
        </Button>
    </Tooltip>
</div>

{#if visibleItems}
    <div class="table-wrapper">
        <div class="log-scroll" bind:this={scrollEl}>
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
                <div
                    class="virtual-spacer"
                    style="height: {virtualItems[0]?.start ?? 0}px"
                ></div>
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
                                        <a
                                            href="/status/sessions/{item.sessionId}"
                                            use:link
                                        >
                                            {item.sessionId}
                                        </a>
                                    {/if}
                                </div>
                            {/if}
                            <div class="content">
                                {#if richEntry?._type === 'AccessRoleGranted1'}
                                    <div class="rich-entry">
                                        Granted
                                        <AccessRoleBadge
                                            id={richEntry.role_id}
                                            name={richEntry.role_name}
                                        />
                                        access role to
                                        <UserBadge
                                            id={richEntry.grantee_id}
                                            name={richEntry.grantee_username}
                                        />
                                    </div>
                                {:else if richEntry?._type === 'AccessRoleRevoked1'}
                                    <div class="rich-entry">
                                        Revoked
                                        <AccessRoleBadge
                                            id={richEntry.role_id}
                                            name={richEntry.role_name}
                                        />
                                        access role from
                                        <UserBadge
                                            id={richEntry.grantee_id}
                                            name={richEntry.grantee_username}
                                        />
                                    </div>
                                {:else if richEntry?._type === 'AdminRoleGranted1'}
                                    <div class="rich-entry">
                                        Granted
                                        <AdminRoleBadge
                                            id={richEntry.admin_role_id}
                                            name={richEntry.admin_role_name}
                                        />
                                        admin role to
                                        <UserBadge
                                            id={richEntry.grantee_id}
                                            name={richEntry.grantee_username}
                                        />
                                    </div>
                                {:else if richEntry?._type === 'AdminRoleRevoked1'}
                                    <div class="rich-entry">
                                        Revoked
                                        <AdminRoleBadge
                                            id={richEntry.admin_role_id}
                                            name={richEntry.admin_role_name}
                                        />
                                        admin role from
                                        <UserBadge
                                            id={richEntry.grantee_id}
                                            name={richEntry.grantee_username}
                                        />
                                    </div>
                                {:else if richEntry?._type === 'UserCreated1'}
                                    <div class="rich-entry">
                                        Created user
                                        <UserBadge
                                            id={richEntry.user_id}
                                            name={richEntry.username}
                                        />
                                    </div>
                                {:else if richEntry?._type === 'UserDeleted1'}
                                    <div class="rich-entry">
                                        Deleted user
                                        <UserBadge
                                            id={richEntry.user_id}
                                            name={richEntry.username}
                                        />
                                    </div>
                                {:else if richEntry?._type === 'UserAuthenticated1'}
                                    <div class="rich-entry">
                                        Authenticated
                                        <UserBadge
                                            id={richEntry.user_id}
                                            name={richEntry.username}
                                        />
                                        {#if richEntry.credentials}
                                            <span class="badge bg-secondary"
                                                >{richEntry.credentials}</span
                                            >
                                        {/if}
                                        {#if richEntry.client_ip}
                                            <span class="text-muted"
                                                >from
                                                {richEntry.client_ip}</span
                                            >
                                        {/if}
                                    </div>
                                {:else if richEntry?._type === 'UserAuthenticationFailed1'}
                                    <div class="rich-entry auth-failed">
                                        <span class="event-label">
                                            Authentication failed
                                        </span>
                                        {#if richEntry.user_id}
                                            <UserBadge
                                                id={richEntry.user_id}
                                                name={richEntry.username}
                                            />
                                        {:else}
                                            <strong
                                                >{richEntry.username}</strong
                                            >
                                        {/if}
                                        {#if richEntry.credentials}
                                            <span class="badge bg-secondary"
                                                >{richEntry.credentials}</span
                                            >
                                        {/if}
                                        {#if richEntry.reason}
                                            <span
                                                class="badge auth-failed-reason"
                                                >{richEntry.reason}</span
                                            >
                                        {/if}
                                        {#if richEntry.client_ip}
                                            <span class="text-muted"
                                                >from
                                                {richEntry.client_ip}</span
                                            >
                                        {/if}
                                    </div>
                                {:else if richEntry?._type === 'TargetSessionStarted1'}
                                    <div class="rich-entry">
                                        Target session started for
                                        <UserBadge
                                            id={richEntry.user_id}
                                            name={richEntry.username}
                                        />
                                        on target
                                        <TargetBadge
                                            id={richEntry.target_id}
                                            name={richEntry.target_name}
                                        />
                                    </div>
                                {:else if richEntry?._type === 'TargetSessionEnded1'}
                                    <div class="rich-entry">
                                        Target session ended for
                                        <UserBadge
                                            id={richEntry.user_id}
                                            name={richEntry.username}
                                        />
                                        on target
                                        <TargetBadge
                                            id={richEntry.target_id}
                                            name={richEntry.target_name}
                                        />
                                    </div>
                                {:else if richEntry?._type === 'CredentialCreated1'}
                                    <div class="rich-entry">
                                        Added
                                        {richEntry.credential_type}
                                        credential
                                        {#if richEntry.credential_name}
                                            <strong
                                                >{richEntry.credential_name}</strong
                                            >
                                        {/if}
                                        for
                                        <UserBadge
                                            id={richEntry.user_id}
                                            name={richEntry.username}
                                        />
                                        {#if richEntry.via === 'self-service'}
                                            <span class="badge bg-secondary">
                                                self-service
                                            </span>
                                        {/if}
                                    </div>
                                {:else if richEntry?._type === 'CredentialDeleted1'}
                                    <div class="rich-entry">
                                        Removed
                                        {richEntry.credential_type}
                                        credential
                                        {#if richEntry.credential_name}
                                            <strong
                                                >{richEntry.credential_name}</strong
                                            >
                                        {/if}
                                        from
                                        <UserBadge
                                            id={richEntry.user_id}
                                            name={richEntry.username}
                                        />
                                        {#if richEntry.via === 'self-service'}
                                            <span class="badge bg-secondary">
                                                self-service
                                            </span>
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
                                {:else if richEntry?._type === 'WebApprovalBypassed1'}
                                    <div class="rich-entry">
                                        Web approval bypassed for
                                        <UserBadge
                                            id={richEntry.user_id}
                                            name={richEntry.username}
                                        />
                                        on
                                        <strong>{richEntry.target}</strong>
                                    </div>
                                {:else if richEntry?._type === 'KubernetesExecStarted1'}
                                    <div class="rich-entry">
                                        <UserBadge
                                            id={richEntry.user_id}
                                            name={richEntry.username}
                                        />
                                        ran
                                        <strong
                                            >{formatJsonList(
                                                richEntry.command,
                                                ' ',
                                            ) || '(image entrypoint)'}</strong
                                        >
                                        in
                                        <strong
                                            >{richEntry.namespace}/{richEntry.pod}</strong
                                        >
                                        {#if richEntry.container}
                                            container
                                            <strong
                                                >{richEntry.container}</strong
                                            >
                                        {/if}
                                        on
                                        <TargetBadge
                                            id={richEntry.target_id}
                                            name={richEntry.target_name}
                                        />
                                    </div>
                                {:else if richEntry?._type === 'KubernetesAttachStarted1'}
                                    <div class="rich-entry">
                                        <UserBadge
                                            id={richEntry.user_id}
                                            name={richEntry.username}
                                        />
                                        attached to
                                        <strong
                                            >{richEntry.namespace}/{richEntry.pod}</strong
                                        >
                                        {#if richEntry.container}
                                            container
                                            <strong
                                                >{richEntry.container}</strong
                                            >
                                        {/if}
                                        on
                                        <TargetBadge
                                            id={richEntry.target_id}
                                            name={richEntry.target_name}
                                        />
                                    </div>
                                {:else if richEntry?._type === 'KubernetesPortForwardStarted1'}
                                    <div class="rich-entry">
                                        <UserBadge
                                            id={richEntry.user_id}
                                            name={richEntry.username}
                                        />
                                        forwarded
                                        {#if richEntry.ports}
                                            port(s)
                                            <strong
                                                >{formatJsonList(
                                                    richEntry.ports,
                                                    ', ',
                                                )}</strong
                                            >
                                        {/if}
                                        from
                                        <strong
                                            >{richEntry.namespace}/{richEntry.pod}</strong
                                        >
                                        on
                                        <TargetBadge
                                            id={richEntry.target_id}
                                            name={richEntry.target_name}
                                        />
                                    </div>
                                {:else if richEntry?._type === 'KubernetesStreamRejected1'}
                                    <div class="rich-entry">
                                        Cluster rejected
                                        <strong>{richEntry.subresource}</strong>
                                        on
                                        <strong
                                            >{richEntry.namespace}/{richEntry.pod}</strong
                                        >
                                        for
                                        <UserBadge
                                            id={richEntry.user_id}
                                            name={richEntry.username}
                                        />
                                        <span class="badge bg-danger">
                                            {richEntry.status}
                                        </span>
                                    </div>
                                {:else if richEntry?._type === 'KubernetesDebugContainerCreated1'}
                                    <div class="rich-entry">
                                        <UserBadge
                                            id={richEntry.user_id}
                                            name={richEntry.username}
                                        />
                                        added debug container
                                        <strong
                                            >{richEntry.debug_container}</strong
                                        >
                                        ({richEntry.image}) to
                                        <strong
                                            >{richEntry.namespace}/{richEntry.pod}</strong
                                        >
                                        {#if richEntry.target_container}
                                            targeting
                                            <strong
                                                >{richEntry.target_container}</strong
                                            >
                                        {/if}
                                        on
                                        <TargetBadge
                                            id={richEntry.target_id}
                                            name={richEntry.target_name}
                                        />
                                    </div>
                                {:else if richEntry?._type === 'KubernetesPodCreated1'}
                                    <div class="rich-entry">
                                        <UserBadge
                                            id={richEntry.user_id}
                                            name={richEntry.username}
                                        />
                                        created pod
                                        <strong
                                            >{richEntry.namespace}/{richEntry.pod}</strong
                                        >
                                        ({formatJsonList(richEntry.images, ', ')})
                                        {#if richEntry.node_name}
                                            on node
                                            <strong
                                                >{richEntry.node_name}</strong
                                            >
                                        {/if}
                                        on
                                        <TargetBadge
                                            id={richEntry.target_id}
                                            name={richEntry.target_name}
                                        />
                                        {#if richEntry.privileged === 'true'}
                                            <span class="badge bg-danger">
                                                privileged
                                            </span>
                                        {/if}
                                        {#if richEntry.host_pid === 'true'}
                                            <span class="badge bg-warning">
                                                hostPID
                                            </span>
                                        {/if}
                                        {#if richEntry.host_network === 'true'}
                                            <span class="badge bg-warning">
                                                hostNetwork
                                            </span>
                                        {/if}
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
                <div
                    class="virtual-spacer"
                    style="height: {Math.max(0, $virtualizerStore.getTotalSize() - (virtualItems.at(-1)?.end ?? 0))}px"
                ></div>
            </div>
            {#if !endReached}
                {#if !loading}
                    <div class="load-older-footer">
                        <IntersectionObserver
                            element={loadOlderButton}
                            on:observe={event => {
                            if (!loading && !error && event.detail.isIntersecting && !endReached) {
                                loadOlder()
                            }
                        }}
                        >
                            <button
                                type="button"
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
                <div class="end-of-log text-muted small py-2">
                    End of the log
                </div>
            {/if}
        </div>
    </div>
{/if}

<style lang="scss">
    .log-toolbar {
        display: flex;
        align-items: center;
        gap: var(--wg-space-sm);
        margin-bottom: var(--wg-space-sm);
    }

    .log-search {
        flex: 1 1 auto;
        min-width: 12rem;
    }

    .table-wrapper {
        flex: 1 0 0;
        min-height: 500px;
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
        background: var(--wg-surface);
        font-family: var(--wg-font-mono);
        font-size: 0.75rem;
        font-weight: 600;
        padding: 0.25rem 0;
        border-bottom: 2px solid var(--wg-border-strong);
        white-space: nowrap;
    }

    .log-row {
        grid-column: 1 / -1;
        display: grid;
        grid-template-columns: subgrid;
        align-items: start;
        box-sizing: border-box;
        border-bottom: var(--wg-border-width) solid var(--wg-border);
        font-family: var(--wg-font-mono);
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
            column-gap: 1rem;

            .text {
                font-weight: bold;
            }

            .key-value {
                white-space: nowrap;
                gap: .75rem;

                .key {
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
                    color: var(--wg-error);
                }

                .auth-failed-reason {
                    background: var(--wg-error-container);
                    border: var(--wg-border-width) solid var(--wg-error);
                    color: var(--wg-on-error-container);
                }
            }
        }
    }

    .load-older-footer {
        padding: 0.75rem 0;
    }

    .end-of-log {
        font-family: var(--wg-font-mono);
        font-size: 0.75rem;
    }

</style>
