<script lang="ts">
    import { api, type Role, type User, type UserRoleAssignmentResponse, type UserRoleHistoryEntry } from 'admin/lib/api'
    import { serverInfo } from 'gateway/lib/store'
    import AsyncButton from 'common/AsyncButton.svelte'
    import { replace } from 'svelte-spa-router'
    import { Dropdown, DropdownItem, DropdownMenu, DropdownToggle, FormGroup, Input, Button, Modal, ModalBody, ModalFooter } from '@sveltestrap/sveltestrap'
    import ModalHeader from 'common/sveltestrap-s5-ports/ModalHeader.svelte'
    import { stringifyError } from 'common/errors'
    import Alert from 'common/sveltestrap-s5-ports/Alert.svelte'
    import CredentialEditor from '../CredentialEditor.svelte'
    import Loadable from 'common/Loadable.svelte'
    import RateLimitInput from 'common/RateLimitInput.svelte'
    import Fa from 'svelte-fa'
    import { faCaretDown, faLink, faUnlink, faClock } from '@fortawesome/free-solid-svg-icons'
    import RelativeDate from '../RelativeDate.svelte'

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

    // Quick expiry preset options
    const expiryPresets = [
        { label: 'Custom...', value: 'custom' },
        { label: '4 hours', value: '4h', ms: 4 * 60 * 60 * 1000 },
        { label: '8 hours', value: '8h', ms: 8 * 60 * 60 * 1000 },
        { label: '12 hours', value: '12h', ms: 12 * 60 * 60 * 1000 },
        { label: '1 day', value: '1d', ms: 24 * 60 * 60 * 1000 },
        { label: '3 days', value: '3d', ms: 3 * 24 * 60 * 60 * 1000 },
        { label: '7 days', value: '7d', ms: 7 * 24 * 60 * 60 * 1000 },
    ]

    function applyPreset(presetValue: string) {
        selectedPreset = presetValue
        if (presetValue === 'custom') {
            return
        }
        const preset = expiryPresets.find(p => p.value === presetValue)
        if (preset?.ms) {
            const newDate = new Date(Date.now() + preset.ms)
            expiryDate = newDate.toISOString().slice(0, 16)
        }
    }

    const initPromise = init()

    async function init () {
        user = await api.getUser({ id: params.id })
        user.credentialPolicy ??= {}

        allRoles = await api.getRoles()
        userRoles = await api.getUserRoles(user)
        roleIsAllowed = Object.fromEntries(userRoles.map(r => [r.roleId, true]))

        // Load role history
        await loadAllRoleHistory()
    }

    async function update () {
        try {
            user = await api.updateUser({
                id: params.id,
                userDataRequest: user!,
            })
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
        const activeAssignment = userRoles.find(r => r.roleId === role.id && !r.isExpired)
        // Check if there's an expired assignment
        const expiredAssignment = userRoles.find(r => r.roleId === role.id && r.isExpired)

        if (activeAssignment) {
            // Remove active role (soft delete - sets revoked_at)
            await api.deleteUserRole({
                id: user!.id,
                roleId: role.id,
            })
            userRoles = userRoles.filter(r => r.roleId !== role.id)
            roleIsAllowed = { ...roleIsAllowed, [role.id]: false }
        } else if (expiredAssignment) {
            // Re-enable expired role by removing the expiry (makes it permanent)
            await api.removeUserRoleExpiry({
                id: user!.id,
                roleId: role.id,
            })
            await init()
        } else {
            // Add new role
            await api.addUserRole({
                id: user!.id,
                roleId: role.id,
                addUserRoleRequest: {},
            })
            await init()
        }
    }

    function openExpiryModal(roleAssignment: UserRoleAssignmentResponse) {
        editingRole = roleAssignment
        expiryDate = roleAssignment.expiresAt ? new Date(roleAssignment.expiresAt).toISOString().slice(0, 16) : null
        selectedPreset = 'custom'
        showExpiryModal = true
    }

    async function saveExpiry() {
        if (!editingRole) {
            return
        }

        try {
            const expiresAt = expiryDate ? new Date(expiryDate) : undefined

            if (expiresAt) {
                // Updating existing role expiry
                await api.updateUserRoleExpiry({
                    id: user!.id,
                    roleId: editingRole.roleId,
                    updateUserRoleExpiryRequest: {
                        expiresAt,
                    },
                })
            } else {
                // Removing expiry (making permanent)
                await api.removeUserRoleExpiry({
                    id: user!.id,
                    roleId: editingRole.roleId,
                })
            }
            showExpiryModal = false
            await init()
            error = null
        } catch (err) {
            error = await stringifyError(err)
        }
    }

    async function removeExpiry() {
        if (!editingRole) {
            return
        }
        await api.removeUserRoleExpiry({
            id: user!.id,
            roleId: editingRole.roleId,
        })
        showExpiryModal = false
        await init()
    }

    function getExpiryStatus(assignment: UserRoleAssignmentResponse): { text: string, 'class': string } {
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
    let historyLimit = $state(10)

    async function loadAllRoleHistory() {
        if (!user) {
            return []
        }

        const allHistory: UserRoleHistoryEntry[] = []
        for (const roleAssignment of userRoles) {
            try {
                const history = await api.getUserRoleHistory({
                    id: user.id,
                    roleId: roleAssignment.roleId,
                })
                allHistory.push(...history)
            } catch {
                // Ignore errors for individual role history
            }
        }

        // Sort by date descending
        roleHistory = allHistory.sort((a, b) =>
            new Date(b.occurredAt).getTime() - new Date(a.occurredAt).getTime()
        )
        return roleHistory
    }

    function getActionLabel(action: string): string {
        switch (action) {
            case 'granted':
                return 'Role granted'
            case 'revoked':
                return 'Role revoked'
            case 'expiry_changed':
                return 'Expiry updated'
            case 'expiry_removed':
                return 'Expiry removed'
            default:
                return action
        }
    }

    function getActionColor(action: string): string {
        switch (action) {
            case 'granted':
                return 'success'
            case 'revoked':
                return 'danger'
            case 'expiry_changed':
                return 'warning'
            case 'expiry_removed':
                return 'info'
            default:
                return 'secondary'
        }
    }

    function formatHistoryDate(date: Date | null | undefined): string {
        if (!date) {
            return 'Permanent'
        }
        return date.toLocaleString()
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
                    {@const roleAssignment = userRoles.find(ur => ur.roleId === role.id && !ur.isExpired)}
                    {@const isAssigned = !!roleAssignment}
                    <div class="list-group-item d-flex align-items-center justify-content-between">
                        <div class="d-flex align-items-center gap-3">
                            <Input
                                id="role-{role.id}"
                                class="mb-0"
                                type="switch"
                                on:change={() => toggleRole(role)}
                                checked={isAssigned} />
                            <div>
                                <div>{role.name}</div>
                                {#if isAssigned && roleAssignment}
                                    <div class="d-flex gap-2 align-items-center">
                                        <small class={getExpiryStatus(roleAssignment).class}>
                                            {getExpiryStatus(roleAssignment).text}
                                        </small>
                                        {#if roleAssignment.grantedAt}
                                            <small class="text-muted" title={new Date(roleAssignment.grantedAt).toLocaleString()}>
                                                &bull; <RelativeDate date={new Date(roleAssignment.grantedAt)} />
                                            </small>
                                        {/if}
                                    </div>
                                {:else if role.description}
                                    <small class="text-muted">{role.description}</small>
                                {/if}
                            </div>
                        </div>
                        {#if isAssigned}
                            <div class="d-flex gap-2">
                                <Button
                                    size="sm"
                                    outline
                                    color="secondary"
                                    on:click={() => openExpiryModal(roleAssignment)}
                                    title="Edit expiry"
                                >
                                    <Fa icon={faClock} />
                                </Button>
                            </div>
                        {/if}
                    </div>
                {/each}
            </div>

            <h4 class="mt-4">Traffic</h4>
            <FormGroup class="mb-5">
                <label for="rateLimitBytesPerSecond">Global bandwidth limit</label>
                <RateLimitInput
                    id="rateLimitBytesPerSecond"
                    bind:value={user.rateLimitBytesPerSecond}
                />
            </FormGroup>

            <!-- Role History Section -->
            <h4 class="mt-4">Role History</h4>
            {#if roleHistory.length === 0}
                <p class="text-muted">No role history entries yet.</p>
            {:else}
                <div class="list-group list-group-flush mb-3">
                    {#each roleHistory.slice(0, historyLimit) as entry (entry.id)}
                        <div class="list-group-item">
                            <div class="d-flex justify-content-between align-items-start">
                                <div>
                                    <span class="badge bg-{getActionColor(entry.action)} me-2">
                                        {getActionLabel(entry.action)}
                                    </span>
                                    <strong>{allRoles.find(r => r.id === entry.roleId)?.name || 'Unknown role'}</strong>
                                </div>
                                <small class="text-muted" title={entry.occurredAt.toLocaleString()}>
                                    <RelativeDate date={entry.occurredAt} />
                                </small>
                            </div>

                            {#if entry.actorUsername}
                                <small class="text-muted d-block mt-1">by {entry.actorUsername}</small>
                            {/if}

                            {#if entry.details}
                                <div class="mt-1 small text-muted">
                                    {#if entry.action === 'expiry_changed'}
                                        {#if entry.details.oldExpiresAt}
                                            Previous: {formatHistoryDate(entry.details.oldExpiresAt)}
                                        {/if}
                                        &rarr; {formatHistoryDate(entry.details.newExpiresAt)}
                                    {:else if entry.action === 'granted' && entry.details.expiresAt}
                                        Expires: {formatHistoryDate(entry.details.expiresAt)}
                                    {/if}
                                </div>
                            {/if}
                        </div>
                    {/each}
                </div>
                {#if roleHistory.length > historyLimit}
                    <div class="text-center mb-3">
                        <Button
                            outline
                            color="secondary"
                            size="sm"
                            on:click={() => { historyLimit += 10 }}
                        >
                            Load more ({roleHistory.length - historyLimit} remaining)
                        </Button>
                    </div>
                {/if}
            {/if}
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
        Set Expiry for {editingRole?.roleName}
    </ModalHeader>
    <ModalBody>
        {#if editingRole}
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
                    on:input={() => { selectedPreset = 'custom' }}
                />
            </FormGroup>

            <!-- No expiry toggle -->
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
                        }
                    }}
                />
                <label class="form-check-label" for="no-expiry">No expiry (permanent)</label>
            </div>

            {#if error}
                <Alert color="danger" dismissible on:dismiss={() => error = null}>
                    {error}
                </Alert>
            {/if}
        {/if}
    </ModalBody>
    <ModalFooter class="d-flex justify-content-between">
        <div>
            {#if editingRole?.expiresAt}
                <Button
                    outline
                    color="danger"
                    on:click={removeExpiry}
                >
                    Make Permanent
                </Button>
            {/if}
        </div>
        <div class="d-flex gap-2">
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
                Save
            </AsyncButton>
        </div>
    </ModalFooter>
</Modal>


