<script lang="ts">
    import { api, type Role, type User, type UserRoleAssignmentResponse, type AdminRole } from 'admin/lib/api'
    import { serverInfo } from 'gateway/lib/store'
    import AsyncButton from 'common/AsyncButton.svelte'
    import { Dropdown, DropdownItem, DropdownMenu, DropdownToggle, FormGroup, Input, Button, Modal, ModalBody, ModalFooter } from '@sveltestrap/sveltestrap'
    import ModalHeader from 'common/sveltestrap-s5-ports/ModalHeader.svelte'
    import { replace, link } from 'svelte-spa-router'
    import { stringifyError } from 'common/errors'
    import Alert from 'common/sveltestrap-s5-ports/Alert.svelte'
    import CredentialEditor from '../CredentialEditor.svelte'
    import Loadable from 'common/Loadable.svelte'
    import RateLimitInput from 'common/RateLimitInput.svelte'
    import Fa from 'svelte-fa'
    import { faCaretDown, faLink, faUnlink, faWrench, faPlus, faTrash } from '@fortawesome/free-solid-svg-icons'
    import RelativeDate from '../RelativeDate.svelte'
    import { onMount, onDestroy } from 'svelte'
    import { adminPermissions } from 'admin/lib/store'
    import AdminRolePermissionsBadge from './AdminRolePermissionsBadge.svelte'
    import Tooltip from 'common/sveltestrap-s5-ports/Tooltip.svelte'
    import { formatDistanceToNow } from 'date-fns'

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
    let selectedExpiryPreset: string | null = $state(null)

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
        { label: 'Never', value: null },
        { label: 'Custom...', value: 'custom' },
        { label: '4 hours', value: '4h', ms: 4 * 60 * 60 * 1000 },
        { label: '8 hours', value: '8h', ms: 8 * 60 * 60 * 1000 },
        { label: '12 hours', value: '12h', ms: 12 * 60 * 60 * 1000 },
        { label: '1 day', value: '1d', ms: 24 * 60 * 60 * 1000 },
        { label: '3 days', value: '3d', ms: 3 * 24 * 60 * 60 * 1000 },
        { label: '7 days', value: '7d', ms: 7 * 24 * 60 * 60 * 1000 },
        { label: '30 days', value: '30d', ms: 30 * 24 * 60 * 60 * 1000 },
    ]

    function applyPreset(presetValue: string|null) {
        selectedExpiryPreset = presetValue
        if (presetValue === null) {
            expiryDate = null
            return
        }
        const preset = expiryPresets.find(p => p.value === presetValue)
        if (preset?.ms) {
            const newDate = new Date(Date.now() + preset.ms)
            expiryDate = toLocalISO(newDate)
        }
    }

    let allAdminRoles: AdminRole[] = $state([])
    let adminRoleIsAllowed: Record<string, any> = $state({})

    const initPromise = init()

    async function init () {
        user = await api.getUser({ id: params.id })
        user.credentialPolicy ??= {}

        allRoles = await api.getRoles()
        userRoles = await api.getUserRoles(user)
        roleIsAllowed = Object.fromEntries(userRoles.map(r => [r.id, true]))
        const allowedRoles = await api.getUserRoles(user)
        roleIsAllowed = Object.fromEntries(allowedRoles.map(r => [r.id, true]))

        allAdminRoles = await api.getAdminRoles()
        const allowedAdmins = await api.getUserAdminRoles({ id: user.id })
        adminRoleIsAllowed = Object.fromEntries(allowedAdmins.map(r => [r.id, true]))
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
        const activeAssignment = userRoles.find(r => r.id === role.id && r.isActive)
        // Check if there's an expired assignment
        const expiredAssignment = userRoles.find(r => r.id === role.id && r.isExpired)

        if (activeAssignment) {
            await api.deleteUserRole({
                id: user!.id,
                roleId: role.id,
            })
            roleIsAllowed = { ...roleIsAllowed, [role.id]: false }
        } else if (expiredAssignment) {
            await api.updateUserRole({
                id: user!.id,
                roleId: role.id,
                updateUserRoleRequest: { expiresAt: undefined },
            })
            roleIsAllowed = { ...roleIsAllowed, [role.id]: true }
        } else {
            await api.addUserRole({
                id: user!.id,
                roleId: role.id,
            })
            roleIsAllowed = { ...roleIsAllowed, [role.id]: true }
        }

        userRoles = await api.getUserRoles(user!)
    }

    function toLocalISO (date: Date): string {
        const tzOffset = date.getTimezoneOffset() * 60000
        const localISOTime = new Date(date.getTime() - tzOffset).toISOString().slice(0, -5)
        return localISOTime
    }

    function nowLocalISO(): string {
        return toLocalISO(new Date())
    }

    function openExpiryModal(roleAssignment: UserRoleAssignmentResponse) {
        editingRole = roleAssignment
        expiryDate = roleAssignment.expiresAt ? toLocalISO(roleAssignment.expiresAt) : null
        selectedExpiryPreset = expiryDate ? 'custom' : null
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

            if (expiresAt) {
                await api.updateUserRole({
                    id: user!.id,
                    roleId: editingRole!.id,
                    updateUserRoleRequest: { expiresAt },
                })
            } else {
                await api.updateUserRole({
                    id: user!.id,
                    roleId: editingRole!.id,
                    updateUserRoleRequest: { expiresAt: undefined },
                })
            }

            showExpiryModal = false
            userRoles = await api.getUserRoles(user!)
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

        const totalHours = Math.round(msUntilExpiry / (1000 * 60 * 60))
        const totalDays = Math.round(msUntilExpiry / (1000 * 60 * 60 * 24))

        const text = `Expires in ${formatDistanceToNow(expiry)}`

        const urgencyClass = totalHours < 1
            ? 'text-danger'
            : totalDays <= 7
                ? 'text-warning'
                : 'text-muted'

        return { text, 'class': urgencyClass }
    }

    async function toggleAdminRole (role: AdminRole) {
        if (adminRoleIsAllowed[role.id]) {
            await api.deleteUserAdminRole({
                id: user!.id,
                roleId: role.id,
            })
            adminRoleIsAllowed = { ...adminRoleIsAllowed, [role.id]: false }
        } else {
            await api.addUserAdminRole({
                id: user!.id,
                roleId: role.id,
            })
            adminRoleIsAllowed = { ...adminRoleIsAllowed, [role.id]: true }
        }
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

    const cidrRegex = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$|^[0-9a-fA-F:]+\/\d{1,3}$/
    function isValidCidr (value: string | undefined | null): boolean {
        if (!value?.trim()) {return true}
        return cidrRegex.test(value.trim())
    }

    function addIpRange () {
        if (!user) {return}
        if (!user.allowedIpRanges) {user.allowedIpRanges = []}
        user.allowedIpRanges = [...user.allowedIpRanges, '']
    }

    function removeIpRange (index: number) {
        if (!user?.allowedIpRanges) {return}
        user.allowedIpRanges = user.allowedIpRanges.filter((_, i) => i !== index)
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

        {#if $adminPermissions.usersEdit}
        <CredentialEditor
            userId={user.id}
            username={user.username}
            bind:credentialPolicy={user.credentialPolicy!}
            ldapLinked={!!user.ldapServerId}
        />
        {/if}

        <h4 class="mt-4">User roles</h4>
        <div class="list-group list-group-flush mb-3">
            {#each allRoles as role (role.id)}
                {@const activeAssignment = userRoles.find(ur => ur.id === role.id && ur.isActive)}
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
                                            <RelativeDate date={expiredAssignment.expiresAt} />
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
                                id="options-button-{role.id}"
                                color="link"
                                on:click={() => openExpiryModal(activeAssignment)}
                            >
                                <Fa icon={faWrench}/>
                            </Button>
                            <Tooltip target="options-button-{role.id}" delay="500">
                                Options
                            </Tooltip>
                        {/if}
                    </div>
                </div>
            {/each}
        </div>

        <h4 class="mt-4">Admin roles</h4>
        <div class="list-group list-group-flush mb-3">
            {#each allAdminRoles as role (role.id)}
                <label
                    for="admin-role-{role.id}"
                    class="list-group-item list-group-item-action d-flex align-items-center"
                >
                    <Input
                        id="admin-role-{role.id}"
                        class="mb-0 me-2"
                        type="switch"
                        on:change={() => toggleAdminRole(role)}
                        disabled={!$adminPermissions.adminRolesManage}
                        checked={adminRoleIsAllowed[role.id]} />
                    <div>
                        <div>{role.name}</div>
                        {#if role.description}
                            <small class="text-muted">{role.description}</small>
                        {/if}
                    </div   >
                    <span class="ms-auto">
                        <AdminRolePermissionsBadge {role} />
                    </span>
                </label>
            {/each}
        </div>

        <h4 class="mt-4">Traffic</h4>
        <FormGroup class="mb-3">
            <label for="rateLimitBytesPerSecond">Global bandwidth limit</label>
            <RateLimitInput
                id="rateLimitBytesPerSecond"
                bind:value={user.rateLimitBytesPerSecond}
            />
        </FormGroup>

        <h4 class="mt-4">Access restrictions</h4>
        <div class="mb-5">
            <!-- svelte-ignore a11y_label_has_associated_control -->
            <label class="form-label">Allowed IP ranges (CIDR)</label>
            {#if user.allowedIpRanges?.length}
                {#each user.allowedIpRanges as range, index (index)}
                    <div class="d-flex align-items-center mb-2 gap-2">
                        <Input
                            placeholder="e.g. 192.168.1.0/24"
                            value={range}
                            on:input={(e) => {
                                if (user?.allowedIpRanges) {
                                    user.allowedIpRanges[index] = e.target.value
                                    user.allowedIpRanges = [...user.allowedIpRanges]
                                }
                            }}
                            invalid={!!range?.trim() && !isValidCidr(range)}
                        />
                        <Button
                            color="danger"
                            outline
                            size="sm"
                            on:click={() => removeIpRange(index)}
                        >
                            <Fa icon={faTrash} />
                        </Button>
                    </div>
                    {#if range?.trim() && !isValidCidr(range)}
                        <small class="form-text text-danger d-block mb-2" style="margin-top: -0.5rem">
                            Invalid CIDR notation. Use a format like 192.168.1.0/24 or 10.0.0.1/32.
                        </small>
                    {/if}
                {/each}
            {/if}
            <Button
                color="secondary"
                outline
                size="sm"
                on:click={addIpRange}
            >
                <Fa icon={faPlus} class="me-1" />Add IP range
            </Button>
            <small class="form-text text-muted d-block mt-2">
                If set, only connections from these IP ranges will be allowed. Use CIDR notation (e.g. 10.0.0.0/8, 192.168.1.0/24, or a single IP like 1.2.3.4/32). Leave empty to allow all IPs.
            </small>
        </div>
        {/if}
    </Loadable>

    {#if error}
        <Alert color="danger">{error}</Alert>
    {/if}

    <div class="d-flex">
        <a href="/log/user/{params.id}" use:link class="btn btn-secondary">
            Audit log
        </a>

        <AsyncButton
            color="primary"
            class="ms-auto"
            click={update}
            disabled={!$adminPermissions.usersEdit}
        >Update</AsyncButton>

        <AsyncButton
            class="ms-2"
            color="danger"
            click={remove}
            disabled={!$adminPermissions.usersDelete}
        >Remove</AsyncButton>
    </div>
</div>

<!-- Expiry Modal -->
<Modal isOpen={showExpiryModal} toggle={() => showExpiryModal = false}>
    <ModalHeader>
        Edit assignment: {editingRole?.name}
    </ModalHeader>
    <ModalBody>
        <!-- Quick expiry presets -->
        <FormGroup floating label="Expiry date">
            <Input
                type="select"
                bind:value={selectedExpiryPreset}
                on:change={() => applyPreset(selectedExpiryPreset)}
            >
                {#each expiryPresets as preset (preset.value)}
                    <option value={preset.value}>{preset.label}</option>
                {/each}
            </Input>
        </FormGroup>

        {#if expiryDate !== null}
            <FormGroup floating label="Expires at">
                <Input
                    type="datetime-local"
                    bind:value={expiryDate}
                    min={nowLocalISO()}
                    on:input={() => { selectedExpiryPreset = 'custom' }}
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
            class="modal-button"
            color="secondary"
            on:click={() => showExpiryModal = false}
        >
            Cancel
        </Button>
        <AsyncButton
            color="primary"
            class="modal-button"
            click={saveExpiry}
        >
            Save
        </AsyncButton>
    </ModalFooter>
</Modal>
