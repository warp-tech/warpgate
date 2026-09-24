<script lang="ts">
    /**
     * User detail — screen 6a: page shell, tabs, danger zone, ConfirmDialog.
     *
     * CredentialEditor (6b) and AllowedIpRangesEditor still delegate to the
     * existing components, the same staging 4a used.
     *
     * ── Enumeration of the old component, asserted present here ──────────
     * State:      error, user, allRoles, userRoles, roleIsAllowed,
     *             allAdminRoles, adminRoleIsAllowed, showExpiryModal,
     *             editingRole, expiryDate, selectedExpiryPreset, _tick
     * Behaviour:  init (credentialPolicy defaulted to {}), update, remove,
     *             toggleRole (three-way), toLocalISO, nowLocalISO,
     *             openExpiryModal, saveExpiry (future-date validation),
     *             getExpiryStatus (urgency tiers), toggleAdminRole,
     *             unlinkFromLdap, autoLinkToLdap, applyPreset
     * Sections:   General, Credentials, Access roles, Admin roles, Network
     * Actions:    Audit log link, Update, Remove
     *
     * ── Behaviour worth spelling out ─────────────────────────────────────
     * `toggleRole` is three-way, not a boolean. An expired assignment is not
     * the same as no assignment: turning it back on clears `expiresAt` via
     * updateUserRole rather than calling addUserRole, which would fail on the
     * existing row.
     *
     * `_tick` increments every 60s purely so `getExpiryStatus` re-evaluates —
     * a role expiring in 59 minutes should not still read "1 hour" ten
     * minutes later.
     *
     * The expiry modal validates that the date is in the future *before*
     * sending, because the API accepts a past date and the assignment then
     * reads as already expired.
     *
     * ── UPSTREAM BUG PRESERVED, NOT FIXED ────────────────────────────────
     * The username field is `disabled={!user.ldapServerId}` — editable for
     * LDAP-linked users, read-only for local ones. That is almost certainly
     * inverted: a directory-sourced username is the one that should not be
     * hand-edited. Preserved verbatim because changing it is a behaviour
     * change, not a presentation one. Flagged for a decision.
     */
    import {
        type AdminRole,
        api,
        type Role,
        type User,
        type UserRoleAssignmentResponse,
    } from 'admin/lib/api'
    import { adminPermissions } from 'admin/lib/store'
    import { stringifyError } from 'common/errors'
    import Loadable from 'common/Loadable.svelte'
    import RateLimitInput from 'common/RateLimitInput.svelte'
    import { formatDistanceToNow } from 'date-fns'
    import { serverInfo } from 'gateway/lib/store'
    import { onDestroy, onMount } from 'svelte'
    import { push, replace } from 'svelte-spa-router'
    import Badge from 'ui/Badge.svelte'
    import Button from 'ui/Button.svelte'
    import Callout from 'ui/Callout.svelte'
    import ConfirmDialog from 'ui/ConfirmDialog.svelte'
    import Input from 'ui/Input.svelte'
    import Modal from 'ui/Modal.svelte'
    import Select from 'ui/Select.svelte'
    import Tabs from 'ui/Tabs.svelte'
    import Toggle from 'ui/Toggle.svelte'
    import { toast } from 'ui/toasts.svelte'
    import AdminRolePermissionsBadge from '../../config/AdminRolePermissionsBadge.svelte'
    import AllowedIpRangesEditor from '../../config/users/AllowedIpRangesEditor.svelte'
    import CredentialEditor from './credentials/CredentialEditor.svelte'

    interface Props {
        params: { id: string }
    }

    let { params }: Props = $props()

    let error: string | null = $state(null)
    let user: User | undefined = $state()
    let allRoles: Role[] = $state([])
    let userRoles: UserRoleAssignmentResponse[] = $state([])
    let roleIsAllowed: Record<string, boolean> = $state({})
    let allAdminRoles: AdminRole[] = $state([])
    let adminRoleIsAllowed: Record<string, boolean> = $state({})

    let showExpiryModal = $state(false)
    let editingRole: UserRoleAssignmentResponse | null = $state(null)
    let expiryDate: string | null = $state(null)
    let selectedExpiryPreset: string | null = $state(null)
    let deleteOpen = $state(false)

    let tab = $state('general')

    // Drives getExpiryStatus so a countdown does not go stale on screen.
    let _tick = $state(0)
    let _tickInterval: ReturnType<typeof setInterval> | null = null

    onMount(() => {
        _tickInterval = setInterval(() => {
            _tick++
        }, 60_000)
    })

    onDestroy(() => {
        if (_tickInterval) {
            clearInterval(_tickInterval)
        }
    })

    const expiryPresets = [
        { label: 'Never', value: '' },
        { label: 'Custom…', value: 'custom' },
        { label: '4 hours', value: '4h', ms: 4 * 60 * 60 * 1000 },
        { label: '8 hours', value: '8h', ms: 8 * 60 * 60 * 1000 },
        { label: '12 hours', value: '12h', ms: 12 * 60 * 60 * 1000 },
        { label: '1 day', value: '1d', ms: 24 * 60 * 60 * 1000 },
        { label: '3 days', value: '3d', ms: 3 * 24 * 60 * 60 * 1000 },
        { label: '7 days', value: '7d', ms: 7 * 24 * 60 * 60 * 1000 },
        { label: '30 days', value: '30d', ms: 30 * 24 * 60 * 60 * 1000 },
    ]

    function applyPreset(presetValue: string | null) {
        selectedExpiryPreset = presetValue
        if (!presetValue) {
            expiryDate = null
            return
        }
        const preset = expiryPresets.find(p => p.value === presetValue)
        if (preset?.ms) {
            expiryDate = toLocalISO(new Date(Date.now() + preset.ms))
        }
    }

    const initPromise = init()

    async function init() {
        const loaded = await api.getUser({ id: params.id })
        loaded.credentialPolicy ??= {}
        user = loaded

        allRoles = await api.getRoles()
        userRoles = await api.getUserRoles(loaded)
        roleIsAllowed = Object.fromEntries(userRoles.map(r => [r.id, true]))

        allAdminRoles = await api.getAdminRoles()
        const allowedAdmins = await api.getUserAdminRoles({ id: loaded.id })
        adminRoleIsAllowed = Object.fromEntries(
            allowedAdmins.map(r => [r.id, true]),
        )
    }

    async function update() {
        const u = user
        if (!u) {
            return
        }
        try {
            user = await api.updateUser({ id: params.id, userDataRequest: u })
            error = null
            toast.success('User saved')
        } catch (err) {
            error = await stringifyError(err)
        }
    }

    async function remove() {
        const u = user
        if (!u) {
            return
        }
        await api.deleteUser(u)
        replace('/config/users')
    }

    // Three-way: active -> revoke, expired -> reinstate by clearing expiry,
    // absent -> grant. An expired assignment still exists, so addUserRole
    // would fail on it.
    async function toggleRole(role: Role) {
        const u = user
        if (!u) {
            return
        }
        const activeAssignment = userRoles.find(
            r => r.id === role.id && r.isActive,
        )
        const expiredAssignment = userRoles.find(
            r => r.id === role.id && r.isExpired,
        )

        if (activeAssignment) {
            await api.deleteUserRole({ id: u.id, roleId: role.id })
            roleIsAllowed = { ...roleIsAllowed, [role.id]: false }
        } else if (expiredAssignment) {
            await api.updateUserRole({
                id: u.id,
                roleId: role.id,
                updateUserRoleRequest: { expiresAt: undefined },
            })
            roleIsAllowed = { ...roleIsAllowed, [role.id]: true }
        } else {
            await api.addUserRole({ id: u.id, roleId: role.id })
            roleIsAllowed = { ...roleIsAllowed, [role.id]: true }
        }

        userRoles = await api.getUserRoles(u)
    }

    // datetime-local wants a local-time string, so the offset is subtracted
    // before serialising rather than sending UTC.
    function toLocalISO(date: Date): string {
        const tzOffset = date.getTimezoneOffset() * 60000
        return new Date(date.getTime() - tzOffset).toISOString().slice(0, -5)
    }

    function nowLocalISO(): string {
        return toLocalISO(new Date())
    }

    function openExpiryModal(roleAssignment: UserRoleAssignmentResponse) {
        editingRole = roleAssignment
        expiryDate = roleAssignment.expiresAt
            ? toLocalISO(roleAssignment.expiresAt)
            : null
        selectedExpiryPreset = expiryDate ? 'custom' : ''
        showExpiryModal = true
    }

    async function saveExpiry() {
        const u = user
        const editing = editingRole
        if (!u || !editing) {
            return
        }
        try {
            const expiresAt = expiryDate ? new Date(expiryDate) : undefined

            // The API accepts a past date, and the assignment then reads as
            // already expired — confusing enough to be worth rejecting here.
            if (expiresAt && expiresAt.getTime() <= Date.now()) {
                error = 'Expiry date must be in the future.'
                return
            }

            await api.updateUserRole({
                id: u.id,
                roleId: editing.id,
                updateUserRoleRequest: { expiresAt },
            })

            showExpiryModal = false
            userRoles = await api.getUserRoles(u)
            error = null
        } catch (err) {
            error = await stringifyError(err)
        }
    }

    type ExpiryUrgency = 'expired' | 'soon' | 'week' | 'permanent' | 'later'

    function getExpiryStatus(assignment: UserRoleAssignmentResponse): {
        text: string
        urgency: ExpiryUrgency
    } {
        // Referenced so this recomputes on the 60s tick
        void _tick

        if (assignment.isExpired) {
            return { text: 'Expired', urgency: 'expired' }
        }
        if (!assignment.expiresAt) {
            return { text: 'Permanent', urgency: 'permanent' }
        }

        const expiry = new Date(assignment.expiresAt)
        const msUntilExpiry = expiry.getTime() - Date.now()

        if (msUntilExpiry <= 0) {
            return { text: 'Expired', urgency: 'expired' }
        }

        const totalHours = Math.round(msUntilExpiry / (1000 * 60 * 60))
        const totalDays = Math.round(msUntilExpiry / (1000 * 60 * 60 * 24))

        return {
            text: `Expires in ${formatDistanceToNow(expiry)}`,
            urgency:
                totalHours < 1 ? 'expired' : totalDays <= 7 ? 'soon' : 'later',
        }
    }

    async function toggleAdminRole(role: AdminRole) {
        const u = user
        if (!u) {
            return
        }
        if (adminRoleIsAllowed[role.id]) {
            await api.deleteUserAdminRole({ id: u.id, roleId: role.id })
            adminRoleIsAllowed = { ...adminRoleIsAllowed, [role.id]: false }
        } else {
            await api.addUserAdminRole({ id: u.id, roleId: role.id })
            adminRoleIsAllowed = { ...adminRoleIsAllowed, [role.id]: true }
        }
    }

    async function unlinkFromLdap() {
        try {
            user = await api.unlinkUserFromLdap({ id: params.id })
            error = null
        } catch (err) {
            error = await stringifyError(err)
        }
    }

    async function autoLinkToLdap() {
        try {
            user = await api.autoLinkUserToLdap({ id: params.id })
            error = null
        } catch (err) {
            error = await stringifyError(err)
        }
    }

    const tabs = $derived([
        { value: 'general', label: 'General' },
        ...($adminPermissions.usersEdit && user?.credentialPolicy
            ? [{ value: 'credentials', label: 'Credentials' }]
            : []),
        { value: 'roles', label: 'Access roles', badge: userRoles.length },
        {
            value: 'admin-roles',
            label: 'Admin roles',
            badge: Object.values(adminRoleIsAllowed).filter(Boolean).length,
        },
        { value: 'network', label: 'Network' },
    ])
</script>

<Loadable promise={initPromise}>
    {#if user}
        {@const u = user}
        <div class="head">
            <div class="head-titles">
                <h1>{u.username}</h1>
                <div class="head-meta">
                    {#if u.ldapServerId}
                        <Badge tone="primary">LDAP linked</Badge>
                    {:else}
                        <Badge>Local account</Badge>
                    {/if}
                </div>
            </div>

            {#if $serverInfo?.hasLdap}
                <Button
                    size="compact"
                    click={u.ldapServerId ? unlinkFromLdap : autoLinkToLdap}
                >
                    {u.ldapServerId ? 'Unlink from LDAP' : 'Auto-link to LDAP'}
                </Button>
            {/if}
        </div>

        {#if error}
            <div class="page-error">
                <Callout tone="danger" title="Something went wrong">
                    {error}
                </Callout>
            </div>
        {/if}

        <Tabs label="User settings" bind:value={tab} {tabs}>
            {#snippet children(active)}
                {#if active === 'general'}
                    <div class="panel">
                        <Input
                            label="Username"
                            mono
                            bind:value={u.username}
                            disabled={!u.ldapServerId}
                        />
                        <Input label="Description" bind:value={u.description} />
                    </div>
                {:else if active === 'credentials'}
                    <div class="panel">
                        {#if u.credentialPolicy}
                            <CredentialEditor
                                userId={u.id}
                                username={u.username}
                                bind:credentialPolicy={u.credentialPolicy}
                                ldapLinked={!!u.ldapServerId}
                            />
                        {/if}
                    </div>
                {:else if active === 'roles'}
                    <div class="panel">
                        <ul class="role-list">
                            {#each allRoles as role (role.id)}
                                {@const activeAssignment = userRoles.find(
                                    ur => ur.id === role.id && ur.isActive,
                                )}
                                {@const expiredAssignment = userRoles.find(
                                    ur => ur.id === role.id && ur.isExpired,
                                )}
                                {@const isActive = !!activeAssignment}
                                {@const assignment =
                                    activeAssignment ?? expiredAssignment}
                                {@const expiry = assignment
                                    ? getExpiryStatus(assignment)
                                    : null}
                                <li
                                    class:expired={!isActive && !!expiredAssignment}
                                >
                                    <Toggle
                                        label={role.name}
                                        hint={role.description || undefined}
                                        checked={isActive}
                                        disabled={!$adminPermissions.accessRolesAssign}
                                        onchange={() => toggleRole(role)}
                                    />
                                    <div class="role-meta">
                                        {#if expiry}
                                            <span
                                                class="expiry expiry-{expiry.urgency}"
                                            >
                                                {expiry.text}
                                            </span>
                                        {/if}
                                        {#if assignment}
                                            <Button
                                                variant="ghost"
                                                size="compact"
                                                disabled={!$adminPermissions.accessRolesAssign}
                                                onclick={() =>
                                                    openExpiryModal(assignment)}
                                            >
                                                Edit expiry
                                            </Button>
                                        {/if}
                                    </div>
                                </li>
                            {/each}
                        </ul>
                    </div>
                {:else if active === 'admin-roles'}
                    <div class="panel">
                        <ul class="role-list">
                            {#each allAdminRoles as role (role.id)}
                                <li>
                                    <Toggle
                                        label={role.name}
                                        hint={role.description || undefined}
                                        checked={adminRoleIsAllowed[role.id]}
                                        disabled={!$adminPermissions.adminRolesManage}
                                        onchange={() => toggleAdminRole(role)}
                                    />
                                    <div class="role-meta">
                                        <AdminRolePermissionsBadge {role} />
                                    </div>
                                </li>
                            {/each}
                        </ul>
                    </div>
                {:else if active === 'network'}
                    <div class="panel">
                        <label
                            class="field-label"
                            for="rateLimitBytesPerSecond"
                        >
                            Global bandwidth limit
                        </label>
                        <RateLimitInput
                            id="rateLimitBytesPerSecond"
                            bind:value={u.rateLimitBytesPerSecond}
                        />
                        <div class="ranges">
                            <AllowedIpRangesEditor
                                bind:ranges={u.allowedIpRanges}
                            />
                        </div>
                    </div>
                {/if}
            {/snippet}
        </Tabs>

        <section class="danger-zone" aria-labelledby="danger-zone-heading">
            <h2 id="danger-zone-heading">Danger zone</h2>
            <div class="danger-row">
                <div>
                    <p class="danger-title">Delete this user</p>
                    <p class="danger-hint">
                        Removes the account, its credentials and its role
                        assignments. Past sessions and audit entries are kept
                        but will no longer link to a user.
                    </p>
                </div>
                <Button
                    variant="destructive"
                    disabled={!$adminPermissions.usersDelete}
                    onclick={() => (deleteOpen = true)}
                >
                    Delete user
                </Button>
            </div>
        </section>

        <div class="action-bar">
            <Button
                class="action-start"
                onclick={() => push(`/log/user/${params.id}`)}
            >
                Audit log
            </Button>
            <Button
                variant="primary"
                click={update}
                disabled={!$adminPermissions.usersEdit}
            >
                Update
            </Button>
        </div>

        <Modal
            bind:open={showExpiryModal}
            title="Edit assignment: {editingRole?.name ?? ''}"
            size="sm"
        >
            <Select
                label="Expiry"
                options={expiryPresets.map(p => ({
                    value: p.value,
                    label: p.label,
                }))}
                value={selectedExpiryPreset ?? ''}
                onchange={e =>
                    applyPreset((e.target as HTMLSelectElement).value)}
            />

            {#if expiryDate !== null}
                <div class="expiry-field">
                    <label class="field-label" for="expires-at"
                        >Expires at</label
                    >
                    <input
                        id="expires-at"
                        class="raw-input"
                        type="datetime-local"
                        min={nowLocalISO()}
                        bind:value={expiryDate}
                        oninput={() => (selectedExpiryPreset = 'custom')}
                    >
                </div>
            {/if}

            {#if error}
                <div class="modal-error">
                    <Callout tone="danger" title="Could not save"
                        >{error}</Callout
                    >
                </div>
            {/if}

            {#snippet footer()}
                <Button onclick={() => (showExpiryModal = false)}
                    >Cancel</Button
                >
                <Button variant="primary" click={saveExpiry}>Save</Button>
            {/snippet}
        </Modal>

        <ConfirmDialog
            bind:open={deleteOpen}
            title="Delete {u.username}?"
            confirmLabel="Delete user"
            confirmText={u.username}
            confirmTextLabel="username"
            onconfirm={remove}
        >
            <p>
                This removes the account, its credentials and every role
                assigned to it. Anyone signed in as this user loses access at
                their next request.
            </p>
        </ConfirmDialog>
    {/if}
</Loadable>

<style>
    .head {
        display: flex;
        align-items: flex-start;
        justify-content: space-between;
        gap: var(--wg-space-lg);
        flex-wrap: wrap;
        margin-bottom: var(--wg-space-lg);
    }

    h1 {
        margin: 0;
        font: var(--wg-text-headline-lg);
    }

    /* Without this the username cannot shrink, so a long one pushes the
       actions off the right edge instead of truncating. */
    .head-titles {
        min-width: 0;
    }

    .head-meta {
        margin-top: var(--wg-space-xs);
    }

    .page-error {
        margin-bottom: var(--wg-space-lg);
    }

    .panel {
        display: flex;
        flex-direction: column;
        gap: var(--wg-space-lg);
        max-width: 44rem;
    }

    .role-list {
        list-style: none;
        margin: 0;
        padding: 0;
        border: var(--wg-border-width) solid var(--wg-border);
        border-radius: var(--wg-radius-panel);
        overflow: hidden;
    }

    .role-list li {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: var(--wg-space-lg);
        padding: var(--wg-space-md);
        border-bottom: var(--wg-border-width) solid var(--wg-border);
    }

    .role-list li:last-child {
        border-bottom: 0;
    }

    /* An expired assignment is still an assignment — dimmed, not hidden */
    .role-list li.expired {
        opacity: 0.7;
    }

    .role-meta {
        display: flex;
        align-items: center;
        gap: var(--wg-space-md);
        flex: none;
    }

    .expiry {
        font: var(--wg-text-label-sm);
        font-variant-numeric: tabular-nums;
        white-space: nowrap;
    }

    .expiry-expired {
        color: var(--wg-error);
    }

    .expiry-soon {
        color: var(--wg-secondary);
    }

    .expiry-permanent,
    .expiry-later {
        color: var(--wg-text-subtle);
    }

    .field-label {
        display: block;
        margin-bottom: var(--wg-space-xs);
        font: var(--wg-text-body-md);
        color: var(--wg-text-muted);
    }

    .ranges {
        margin-top: var(--wg-space-lg);
    }

    .expiry-field {
        margin-top: var(--wg-space-lg);
    }

    .modal-error {
        margin-top: var(--wg-space-lg);
    }

    .raw-input {
        width: 100%;
        height: var(--wg-control-height);
        padding: 0 var(--wg-space-sm);
        background: var(--wg-surface-sunken);
        border: var(--wg-border-width) solid var(--wg-border-strong);
        border-radius: var(--wg-radius-control);
        color: var(--wg-text);
        font: var(--wg-text-body-md);
    }

    .raw-input:focus-visible {
        outline: var(--wg-focus-ring);
        outline-offset: var(--wg-focus-ring-offset);
        border-color: var(--wg-primary);
    }

    .danger-zone {
        margin-top: var(--wg-space-3xl);
        padding: var(--wg-space-lg);
        border: var(--wg-border-width) solid var(--wg-error);
        border-radius: var(--wg-radius-panel);
        background: var(--wg-surface-container);
    }

    .danger-zone h2 {
        margin: 0 0 var(--wg-space-md);
        font: var(--wg-text-headline-md);
        color: var(--wg-error);
    }

    .danger-row {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: var(--wg-space-lg);
        flex-wrap: wrap;
    }

    .danger-title {
        margin: 0;
        font: var(--wg-text-label-md);
    }

    .danger-hint {
        margin: var(--wg-space-xs) 0 0;
        max-width: 52ch;
        font: var(--wg-text-body-md);
        color: var(--wg-text-muted);
    }

    .action-bar {
        position: sticky;
        bottom: 0;
        display: flex;
        align-items: center;
        gap: var(--wg-space-sm);
        margin-top: var(--wg-space-xl);
        padding: var(--wg-space-md) 0;
        background: var(--wg-surface);
        border-top: var(--wg-border-width) solid var(--wg-border);
    }

    .action-bar :global(.action-start) {
        margin-right: auto;
    }

    @media (max-width: 640px) {
        h1 {
            font: var(--wg-text-headline-lg-mobile);
        }

        .role-list li {
            flex-direction: column;
            align-items: stretch;
        }
    }
</style>
