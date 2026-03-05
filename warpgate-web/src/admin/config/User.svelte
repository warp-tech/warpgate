<script lang="ts">
    import { api, type Role, type User, type UserRoleAssignmentResponse, type UserRoleHistoryEntry, type SessionSnapshot } from 'admin/lib/api'
    import { serverInfo } from 'gateway/lib/store'
    import AsyncButton from 'common/AsyncButton.svelte'
    import { replace } from 'svelte-spa-router'
    import { Dropdown, DropdownItem, DropdownMenu, DropdownToggle, FormGroup, Input, Button, Modal, ModalBody, ModalFooter, Collapse, Card, CardBody } from '@sveltestrap/sveltestrap'
    import ModalHeader from 'common/sveltestrap-s5-ports/ModalHeader.svelte'
    import { stringifyError } from 'common/errors'
    import Alert from 'common/sveltestrap-s5-ports/Alert.svelte'
    import CredentialEditor from '../CredentialEditor.svelte'
    import Loadable from 'common/Loadable.svelte'
    import RateLimitInput from 'common/RateLimitInput.svelte'
    import Fa from 'svelte-fa'
    import { faCaretDown, faLink, faUnlink, faClock, faUser, faHistory, faTerminal, faDatabase, faGlobe, faChevronDown, faChevronUp, faRedo } from '@fortawesome/free-solid-svg-icons'
    import RelativeDate from '../RelativeDate.svelte'
    import { onMount, onDestroy } from 'svelte'

    interface Props {
        params: { id: string };
    }

    let { params }: Props = $props()

    let error: string|null = $state(null)
    let user: User | undefined = $state()
    let allRoles: Role[] = $state([])
    let userRoles: UserRoleAssignmentResponse[] = $state([])
    let roleIsAllowed: Record<string, any> = $state({})

    // Modal states
    let showExpiryModal = $state(false)
    let editingRole: UserRoleAssignmentResponse | null = $state(null)
    let expiryDate: string | null = $state(null)
    let selectedPreset: string = $state('custom')
    let isNewAssignment = $state(false)
    let pendingRole: Role | null = $state(null)

    // Live countdown tick
    let _tick = $state(0)
    let _tickInterval: ReturnType<typeof setInterval> | null = null

    onMount(() => {
        _tickInterval = setInterval(() => { _tick++ }, 60_000)
    })

    onDestroy(() => {
        if (_tickInterval) {
            clearInterval(_tickInterval)
        }
    })

    // Quick expiry preset options
    const expiryPresets = [
        { label: 'Custom...', value: 'custom' },
        { label: '4 hours', value: '4h', ms: 4 * 60 * 60 * 1000 },
        { label: '8 hours', value: '8h', ms: 8 * 60 * 60 * 1000 },
        { label: '12 hours', value: '12h', ms: 12 * 60 * 60 * 1000 },
        { label: '1 day', value: '1d', ms: 24 * 60 * 60 * 1000 },
        { label: '3 days', value: '3d', ms: 3 * 24 * 60 * 60 * 1000 },
        { label: '7 days', value: '7d', ms: 7 * 24 * 60 * 60 * 1000 },
        { label: '30 days', value: '30d', ms: 30 * 24 * 60 * 60 * 1000 },
    ]

    function applyPreset(presetValue: string) {
        selectedPreset = presetValue
        if (presetValue === 'custom') {
            return
        }
        const preset = expiryPresets.find(p => p.value === presetValue)
        if (preset?.ms) {
            const newDate = new Date(Date.now() + preset.ms)
            expiryDate = toLocalISO(newDate)
        }
    }

    const initPromise = init()

    async function init () {
        user = await api.getUser({ id: params.id })
        user.credentialPolicy ??= {}

        allRoles = await api.getRoles()
        userRoles = await api.getUserRoles(user)
        roleIsAllowed = Object.fromEntries(userRoles.map(r => [r.id, true]))
    }

    async function update () {
        try {
            user = await api.updateUser({
                id: params.id,
                userDataRequest: user!,
            })
            await loadAllRoleHistory()
            error = null
        } catch (err) {
            error = await stringifyError(err)
        }
    }

    async function remove () {
        if (confirm(`Delete user ${user!.username}?`)) {
            await api.deleteUser(user!)
            replace('/config/users')
        }
    }

    async function toggleRole (role: Role) {
        // Check if there's an active (non-expired) assignment
        const activeAssignment = userRoles.find(r => r.id === role.id && !r.isExpired)
        // Check if there's an expired assignment
        const expiredAssignment = userRoles.find(r => r.id === role.id && r.isExpired)

        if (activeAssignment) {
            // Confirm before revoking
            if (!confirm(`Revoke role "${role.name}" from this user?`)) {
                return
            }
            await api.deleteUserRole({
                id: user!.id,
                roleId: role.id,
            })
            userRoles = userRoles.filter(r => r.id !== role.id)
            roleIsAllowed = { ...roleIsAllowed, [role.id]: false }
            await loadAllRoleHistory()
        } else if (expiredAssignment) {
            // Re-enable expired role - show expiry modal to let user choose duration
            openExpiryModalForReEnable(expiredAssignment)
        } else {
            // New assignment - show expiry modal to let user optionally set duration
            openExpiryModalForNewAssignment(role)
        }
    }

    function toLocalISO(date: Date): string {
        const pad = (n: number) => n.toString().padStart(2, '0')
        const year = date.getFullYear()
        const month = pad(date.getMonth() + 1)
        const day = pad(date.getDate())
        const hours = pad(date.getHours())
        const minutes = pad(date.getMinutes())
        return `${year}-${month}-${day}T${hours}:${minutes}`
    }

    function nowLocalISO(): string {
        return toLocalISO(new Date())
    }

    function openExpiryModal(roleAssignment: UserRoleAssignmentResponse) {
        editingRole = roleAssignment
        expiryDate = roleAssignment.expiresAt ? toLocalISO(new Date(roleAssignment.expiresAt)) : null
        selectedPreset = 'custom'
        isNewAssignment = false
        pendingRole = null
        showExpiryModal = true
    }

    function openExpiryModalForNewAssignment(role: Role) {
        editingRole = null
        pendingRole = role
        expiryDate = null
        selectedPreset = 'custom'
        isNewAssignment = true
        showExpiryModal = true
    }

    function openExpiryModalForReEnable(assignment: UserRoleAssignmentResponse) {
        editingRole = assignment
        expiryDate = null
        selectedPreset = 'custom'
        isNewAssignment = true
        pendingRole = null
        showExpiryModal = true
    }

    async function saveExpiry() {
        try {
            const expiresAt = expiryDate ? new Date(expiryDate) : undefined

            // Validate: expiry must be in the future
            if (expiresAt && expiresAt.getTime() <= Date.now()) {
                error = 'Expiry date must be in the future.'
                return
            }

            if (isNewAssignment && pendingRole) {
                // Creating a new assignment with optional expiry
                await api.addUserRole({
                    id: user!.id,
                    roleId: pendingRole.id,
                    addUserRoleRequest: { expiresAt },
                })
            } else if (isNewAssignment && editingRole) {
                // Re-enabling an expired assignment
                if (expiresAt) {
                    await api.updateUserRoleExpiry({
                        id: user!.id,
                        roleId: editingRole.id,
                        updateUserRoleExpiryRequest: { expiresAt },
                    })
                } else {
                    await api.removeUserRoleExpiry({
                        id: user!.id,
                        roleId: editingRole.id,
                    })
                }
            } else if (editingRole) {
                // Editing expiry on an existing active assignment
                if (expiresAt) {
                    await api.updateUserRoleExpiry({
                        id: user!.id,
                        roleId: editingRole.id,
                        updateUserRoleExpiryRequest: { expiresAt },
                    })
                } else {
                    await api.removeUserRoleExpiry({
                        id: user!.id,
                        roleId: editingRole.id,
                    })
                }
            }

            showExpiryModal = false
            await init()
            await loadAllRoleHistory()
            error = null
        } catch (err) {
            error = await stringifyError(err)
        }
    }

    function getExpiryStatus(assignment: UserRoleAssignmentResponse): { text: string, 'class': string } {
        // Reference _tick to make this reactive to the interval
        void _tick

        if (assignment.isExpired) {
            return { text: 'Expired', 'class': 'text-danger' }
        }
        if (!assignment.expiresAt) {
            return { text: 'Permanent', 'class': 'text-muted' }
        }
        const expiry = new Date(assignment.expiresAt)
        const now = new Date()
        const msUntilExpiry = expiry.getTime() - now.getTime()

        if (msUntilExpiry <= 0) {
            return { text: 'Expired', 'class': 'text-danger' }
        }

        const totalMinutes = Math.floor(msUntilExpiry / (1000 * 60))
        const totalHours = Math.floor(msUntilExpiry / (1000 * 60 * 60))
        const totalDays = Math.floor(msUntilExpiry / (1000 * 60 * 60 * 24))

        if (totalHours < 1) {
            return { text: `Expires in ${totalMinutes}min`, 'class': 'text-danger' }
        } else if (totalHours < 24) {
            const hours = totalHours
            const minutes = totalMinutes - (hours * 60)
            if (minutes > 0) {
                return { text: `Expires in ${hours}h ${minutes}min`, 'class': 'text-warning' }
            }
            return { text: `Expires in ${hours}h`, 'class': 'text-warning' }
        } else if (totalDays <= 7) {
            return { text: `Expires in ${totalDays} day${totalDays !== 1 ? 's' : ''}`, 'class': 'text-warning' }
        } else if (totalDays <= 30) {
            return { text: `Expires in ${totalDays} days`, 'class': 'text-muted' }
        } else {
            return { text: `Expires ${expiry.toLocaleDateString()}`, 'class': 'text-muted' }
        }
    }

    // Role history
    let roleHistory: UserRoleHistoryEntry[] = $state([])
    let historyOffset = $state(0)
    let historyPageSize = 50
    let hasMoreHistory = $state(true)
    let roleHistoryLoaded = $state(false)

    async function loadAllRoleHistory(loadMore = false) {
        if (!user) {
            return []
        }

        if (!loadMore) {
            historyOffset = 0
            roleHistory = []
        }

        try {
            const response = await api.getUserAllRoleHistory({
                id: user.id,
                offset: historyOffset,
                limit: historyPageSize,
            })

            if (loadMore) {
                roleHistory = [...roleHistory, ...response.items]
            } else {
                roleHistory = response.items
            }

            hasMoreHistory = roleHistory.length < response.total
            historyOffset += response.items.length
            roleHistoryLoaded = true
        } catch (err) {
            error = await stringifyError(err)
        }

        return roleHistory
    }

    // Session history
    let sessionHistory: SessionSnapshot[] = $state([])
    let sessionOffset = $state(0)
    let sessionPageSize = 50
    let hasMoreSessions = $state(true)
    let sessionHistoryLoaded = $state(false)

    // Collapsible states
    let roleHistoryCollapsed = $state(true)
    let sessionHistoryCollapsed = $state(true)

    // Auto-load history when expanding
    let _prevRoleHistoryCollapsed = true
    let _prevSessionHistoryCollapsed = true

    $effect(() => {
        if (!roleHistoryCollapsed && _prevRoleHistoryCollapsed && !roleHistoryLoaded) {
            loadAllRoleHistory()
        }
        _prevRoleHistoryCollapsed = roleHistoryCollapsed
    })

    $effect(() => {
        if (!sessionHistoryCollapsed && _prevSessionHistoryCollapsed && !sessionHistoryLoaded) {
            loadSessionHistory()
        }
        _prevSessionHistoryCollapsed = sessionHistoryCollapsed
    })

    async function loadSessionHistory(loadMore = false) {
        if (!user) {
            return []
        }

        if (!loadMore) {
            sessionOffset = 0
            sessionHistory = []
        }

        try {
            const response = await api.getSessions({
                username: user.username,
                offset: sessionOffset,
                limit: sessionPageSize,
            })

            if (loadMore) {
                sessionHistory = [...sessionHistory, ...response.items]
            } else {
                sessionHistory = response.items
            }

            hasMoreSessions = sessionHistory.length < response.total
            sessionOffset += response.items.length
            sessionHistoryLoaded = true
        } catch (err) {
            error = await stringifyError(err)
        }

        return sessionHistory
    }

    function getSessionProtocolIcon(protocol: string) {
        if (protocol === 'ssh') {
            return faTerminal
        }
        if (protocol === 'http' || protocol === 'https') {
            return faGlobe
        }
        if (protocol === 'mysql') {
            return faDatabase
        }
        if (protocol === 'postgres') {
            return faDatabase
        }
        return faHistory
    }

    function formatSessionDuration(started: Date, ended?: Date | null): string {
        const start = new Date(started).getTime()
        const end = ended ? new Date(ended).getTime() : Date.now()
        const durationMs = end - start

        const seconds = Math.floor(durationMs / 1000)
        const minutes = Math.floor(seconds / 60)
        const hours = Math.floor(minutes / 60)

        if (hours > 0) {
            return `${hours}h ${minutes % 60}m`
        } else if (minutes > 0) {
            return `${minutes}m ${seconds % 60}s`
        } else {
            return `${seconds}s`
        }
    }

    function getActionDisplayLabel(action: string): string {
        if (action === 'granted') {
            return 'Role granted'
        }
        if (action === 'revoked') {
            return 'Role revoked'
        }
        if (action === 'expiry_changed') {
            return 'Expiry updated'
        }
        if (action === 'expiry_removed') {
            return 'Expiry removed'
        }
        return action
    }

    function getActionDisplayColor(action: string): string {
        if (action === 'granted') {
            return 'success'
        }
        if (action === 'revoked') {
            return 'danger'
        }
        if (action === 'expiry_changed') {
            return 'warning'
        }
        if (action === 'expiry_removed') {
            return 'info'
        }
        return 'secondary'
    }

    function formatHistoryDate(date: Date | string | null | undefined): string {
        if (!date) {
            return 'Permanent'
        }
        return new Date(date).toLocaleString()
    }

    async function unlinkFromLdap () {
        try {
            user = await api.unlinkUserFromLdap({ id: params.id })
            error = null
        } catch (err) {
            error = await stringifyError(err)
        }
    }

    async function autoLinkToLdap () {
        try {
            user = await api.autoLinkUserToLdap({ id: params.id })
            error = null
        } catch (err) {
            error = await stringifyError(err)
        }
    }
</script>

<div class="container-max-md">
    <Loadable promise={initPromise}>
        {#if user}
            <div class="page-summary-bar">
                <div>
                    <h1>{user.username}</h1>
                    <div class="text-muted">User</div>
                </div>
            </div>

            <div class="d-flex align-items-center gap-3">
                <FormGroup floating label="Username" class="flex-grow-1">
                    <Input bind:value={user.username} disabled={!user.ldapServerId} />
                </FormGroup>

                {#if $serverInfo?.hasLdap}
                    <Dropdown class="mb-3">
                        <DropdownToggle color={user.ldapServerId ? 'info' : 'secondary'} class="d-flex align-items-center gap-2">
                            {#if user.ldapServerId}
                                <Fa icon={faLink} fw />
                            {/if}
                            LDAP
                            <Fa icon={faCaretDown} />
                        </DropdownToggle>
                        <DropdownMenu right={true}>
                            {#if user.ldapServerId}
                                <DropdownItem on:click={unlinkFromLdap}>
                                    <Fa icon={faUnlink} fw />
                                    Unlink from LDAP
                                </DropdownItem>
                            {:else}
                                <DropdownItem on:click={autoLinkToLdap}>
                                    <Fa icon={faLink} fw />
                                    Auto-link to LDAP
                                </DropdownItem>
                            {/if}
                        </DropdownMenu>
                    </Dropdown>
                {/if}
            </div>

            <FormGroup floating label="Description">
                <Input bind:value={user.description} />
            </FormGroup>

            <CredentialEditor
                userId={user.id}
                username={user.username}
                bind:credentialPolicy={user.credentialPolicy!}
                ldapLinked={!!user.ldapServerId}
            />

            <h4 class="mt-4">User roles</h4>
            <div class="list-group list-group-flush mb-3">
                {#each allRoles as role (role.id)}
                    {@const activeAssignment = userRoles.find(ur => ur.id === role.id && !ur.isExpired)}
                    {@const expiredAssignment = userRoles.find(ur => ur.id === role.id && ur.isExpired)}
                    {@const isActive = !!activeAssignment}
                    {@const isExpired = !!expiredAssignment && !isActive}
                    {@const assignment = activeAssignment ?? expiredAssignment}
                    {@const status = assignment ? getExpiryStatus(assignment) : null}
                    <div class="list-group-item d-flex align-items-center justify-content-between {isExpired ? 'opacity-75' : ''}">
                        <div class="d-flex align-items-center gap-3">
                            <Input
                                id="role-{role.id}"
                                class="mb-0"
                                type="switch"
                                on:change={() => toggleRole(role)}
                                checked={isActive} />
                            <div>
                                <div class="{isExpired ? 'text-decoration-line-through text-muted' : ''}">{role.name}</div>
                                {#if isActive && activeAssignment}
                                    <div class="d-flex gap-2 align-items-center flex-wrap">
                                        <small class={status?.class ?? ''}>
                                            {status?.text ?? ''}
                                        </small>
                                        {#if activeAssignment.grantedAt}
                                            <small class="text-muted" title={new Date(activeAssignment.grantedAt).toLocaleString()}>
                                                &bull; <RelativeDate date={new Date(activeAssignment.grantedAt)} />
                                            </small>
                                        {/if}
                                    </div>
                                {:else if isExpired && expiredAssignment}
                                    <div class="d-flex gap-2 align-items-center flex-wrap">
                                        <small class="text-danger">
                                            <span class="badge bg-danger bg-opacity-10 text-danger">Expired</span>
                                        </small>
                                        {#if expiredAssignment.expiresAt}
                                            <small class="text-muted">
                                                {new Date(expiredAssignment.expiresAt).toLocaleDateString()}
                                            </small>
                                        {/if}
                                    </div>
                                {:else if role.description}
                                    <small class="text-muted">{role.description}</small>
                                {/if}
                            </div>
                        </div>
                        <div class="d-flex gap-2">
                            {#if isActive && activeAssignment}
                                <Button
                                    size="sm"
                                    outline
                                    color="secondary"
                                    on:click={() => openExpiryModal(activeAssignment)}
                                    title="Edit expiry"
                                >
                                    <Fa icon={faClock} class="me-1" />
                                    Expiry
                                </Button>
                            {:else if isExpired}
                                <Button
                                    size="sm"
                                    outline
                                    color="success"
                                    on:click={() => toggleRole(role)}
                                    title="Re-enable this role"
                                >
                                    <Fa icon={faRedo} class="me-1" />
                                    Re-enable
                                </Button>
                            {/if}
                        </div>
                    </div>
                {/each}
            </div>

            <hr class="mt-4 mb-4" />

            <h4 class="mb-3">Traffic</h4>
            <FormGroup class="mb-5">
                <label for="rateLimitBytesPerSecond">Global bandwidth limit</label>
                <RateLimitInput
                    id="rateLimitBytesPerSecond"
                    bind:value={user.rateLimitBytesPerSecond}
                />
            </FormGroup>

            <!-- Role Assignment History Section -->
            <Card class="mb-4">
                <button
                    type="button"
                    class="card-header d-flex justify-content-between align-items-center w-100 text-start border-0 bg-transparent"
                    style="cursor: pointer"
                    onclick={() => roleHistoryCollapsed = !roleHistoryCollapsed}
                    aria-expanded={!roleHistoryCollapsed}
                    aria-controls="role-history-collapse"
                >
                    <h4 class="mb-0">Role Assignment History</h4>
                    <Fa icon={roleHistoryCollapsed ? faChevronDown : faChevronUp} />
                </button>
                <Collapse isOpen={!roleHistoryCollapsed}>
                    <CardBody>
                        {#if !roleHistoryLoaded}
                            <div class="text-center py-3 text-muted small">Loading history...</div>
                        {:else if roleHistory.length === 0}
                            <div class="text-muted small">No history found for this user.</div>
                        {:else}
                            <div class="list-group list-group-flush mb-3">
                                {#each roleHistory as entry (entry.id)}
                                    <div class="list-group-item py-2 px-0 border-0">
                                        <div class="d-flex justify-content-between align-items-center">
                                            <strong>{entry.details.roleName}</strong>
                                            <span class="badge bg-{getActionDisplayColor(entry.action)}">
                                                {getActionDisplayLabel(entry.action)}
                                            </span>
                                        </div>
                                        <div class="d-flex justify-content-between align-items-center mt-1">
                                            <div class="text-muted small d-flex align-items-center">
                                                <Fa icon={faUser} fw class="me-1" />
                                                <span>
                                                    {entry.actorUsername || 'System'} changed:
                                                    {#if entry.action === 'expiry_changed'}
                                                        {formatHistoryDate(entry.details.oldExpiresAt)} &rarr; {formatHistoryDate(entry.details.newExpiresAt)}
                                                    {:else if entry.details.expiresAt}
                                                        {formatHistoryDate(entry.details.expiresAt)}
                                                    {:else}
                                                        Permanent
                                                    {/if}
                                                </span>
                                            </div>
                                            <div class="text-muted small">{new Date(entry.occurredAt).toLocaleString()}</div>
                                        </div>
                                    </div>
                                {/each}
                            </div>

                            {#if hasMoreHistory}
                                <div class="d-grid mt-2">
                                    <AsyncButton
                                        outline
                                        color="secondary"
                                        click={() => loadAllRoleHistory(true)}
                                    >
                                        Load more
                                    </AsyncButton>
                                </div>
                            {/if}
                        {/if}
                    </CardBody>
                </Collapse>
            </Card>

            <!-- Connection History Section -->
            <Card class="mb-4">
                <button
                    type="button"
                    class="card-header d-flex justify-content-between align-items-center w-100 text-start border-0 bg-transparent"
                    style="cursor: pointer"
                    onclick={() => sessionHistoryCollapsed = !sessionHistoryCollapsed}
                    aria-expanded={!sessionHistoryCollapsed}
                    aria-controls="session-history-collapse"
                >
                    <h4 class="mb-0">Connection History</h4>
                    <Fa icon={sessionHistoryCollapsed ? faChevronDown : faChevronUp} />
                </button>
                <Collapse isOpen={!sessionHistoryCollapsed}>
                    <CardBody>
                        {#if !sessionHistoryLoaded}
                            <div class="text-center py-3 text-muted small">Loading connections...</div>
                        {:else if sessionHistory.length === 0}
                            <div class="text-muted small">No connection history found for this user.</div>
                        {:else}
                            <div class="list-group list-group-flush mb-3">
                                {#each sessionHistory as session (session.id)}
                                    <div class="list-group-item py-3">
                                        <div class="d-flex justify-content-between align-items-start">
                                            <div class="d-flex align-items-center gap-2">
                                                <Fa icon={getSessionProtocolIcon(session.protocol)} class="text-muted" />
                                                <div>
                                                    <strong class="text-capitalize">{session.protocol}</strong>
                                                    {#if session.target?.name}
                                                        <span class="text-muted ms-2">&rarr; {session.target.name}</span>
                                                    {/if}
                                                </div>
                                            </div>
                                            <div class="text-end">
                                                {#if session.ended}
                                                    <span class="badge bg-secondary">Ended</span>
                                                {:else}
                                                    <span class="badge bg-success">Active</span>
                                                {/if}
                                            </div>
                                        </div>
                                        <div class="d-flex justify-content-between align-items-center mt-2">
                                            <div class="text-muted small">
                                                <div>Started: {new Date(session.started).toLocaleString()}</div>
                                                {#if session.ended}
                                                    <div>Ended: {new Date(session.ended).toLocaleString()}</div>
                                                    <div>Duration: {formatSessionDuration(session.started, session.ended)}</div>
                                                {:else}
                                                    <div>Duration: {formatSessionDuration(session.started)}</div>
                                                {/if}
                                            </div>
                                            {#if session.ticketId}
                                                <div class="text-muted small">
                                                    <span class="badge bg-info">Ticket</span>
                                                </div>
                                            {/if}
                                        </div>
                                    </div>
                                {/each}
                            </div>

                            {#if hasMoreSessions}
                                <div class="d-grid mt-2">
                                    <AsyncButton
                                        outline
                                        color="secondary"
                                        click={() => loadSessionHistory(true)}
                                    >
                                        Load more
                                    </AsyncButton>
                                </div>
                            {/if}
                        {/if}
                    </CardBody>
                </Collapse>
            </Card>
        {/if}
    </Loadable>

    {#if error}
        <Alert color="danger">{error}</Alert>
    {/if}

    <div class="d-flex">
        <AsyncButton
            color="primary"
            class="ms-auto"
            click={update}
        >Update</AsyncButton>

        <AsyncButton
            class="ms-2"
            color="danger"
            click={remove}
        >Remove</AsyncButton>
    </div>
</div>

<!-- Expiry Modal -->
<Modal isOpen={showExpiryModal} toggle={() => showExpiryModal = false}>
    <ModalHeader toggle={() => showExpiryModal = false}>
        {#if isNewAssignment}
            Assign role: {pendingRole?.name ?? editingRole?.name}
        {:else}
            Edit expiry: {editingRole?.name}
        {/if}
    </ModalHeader>
    <ModalBody>
        {#if isNewAssignment}
            <p class="text-muted small mb-3">
                Set an optional expiry for this role assignment, or leave as permanent.
            </p>
        {/if}

        <!-- No expiry toggle (shown first for clarity) -->
        <div class="form-check form-switch mb-3">
            <input
                class="form-check-input"
                type="checkbox"
                id="no-expiry"
                checked={expiryDate === null}
                onchange={(e) => {
                    if ((e.target as HTMLInputElement).checked) {
                        expiryDate = null
                        selectedPreset = 'custom'
                    } else {
                        // Default to 7 days when unchecking "permanent"
                        applyPreset('7d')
                    }
                }}
            />
            <label class="form-check-label" for="no-expiry">Permanent (no expiry)</label>
        </div>

        {#if expiryDate !== null}
            <!-- Quick expiry presets -->
            <FormGroup floating label="Quick expiry">
                <Input
                    type="select"
                    bind:value={selectedPreset}
                    on:change={() => applyPreset(selectedPreset)}
                >
                    {#each expiryPresets as preset (preset.value)}
                        <option value={preset.value}>{preset.label}</option>
                    {/each}
                </Input>
            </FormGroup>

            <!-- Date picker -->
            <FormGroup floating label="Expires at">
                <Input
                    type="datetime-local"
                    bind:value={expiryDate}
                    min={nowLocalISO()}
                    on:input={() => { selectedPreset = 'custom' }}
                />
            </FormGroup>
        {/if}

        {#if error}
            <Alert color="danger" dismissible on:dismiss={() => error = null}>
                {error}
            </Alert>
        {/if}
    </ModalBody>
    <ModalFooter>
        <Button
            outline
            color="secondary"
            on:click={() => showExpiryModal = false}
        >
            Cancel
        </Button>
        <AsyncButton
            color="primary"
            click={saveExpiry}
        >
            {isNewAssignment ? 'Assign role' : 'Save'}
        </AsyncButton>
    </ModalFooter>
</Modal>
