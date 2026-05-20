<script lang="ts">
    import { FormGroup, Input } from '@sveltestrap/sveltestrap'
    import { api, type ParameterValues } from 'admin/lib/api'
    import { api as gatewayApi } from 'gateway/lib/api'
    import Loadable from 'common/Loadable.svelte'
    import RateLimitInput from 'common/RateLimitInput.svelte'
    import InfoBox from 'common/InfoBox.svelte'
    import PermissionGate from 'admin/lib/PermissionGate.svelte'
    import { formatDurationAsHumantime, parseHumantimeDuration } from 'common/duration'
    import { reloadServerInfo } from 'gateway/lib/store'

    let parameters: ParameterValues | undefined = $state()
    let hasSsoProviders = $state(false)
    const initPromise = init()

    let durationText = $state('')

    async function init () {
        parameters = await api.getParameters({})
        const ssoProviders = await gatewayApi.getSsoProviders()
        hasSsoProviders = ssoProviders.length > 0
        durationText = parameters.ticketMaxDurationSeconds
            ? formatDurationAsHumantime(parameters.ticketMaxDurationSeconds)
            : ''
    }

    async function update() {
        await api.updateParameters({
            parameterUpdate: parameters!,
        })
        await reloadServerInfo()
    }

    function onDurationChange () {
        const seconds = parseHumantimeDuration(durationText)
        parameters!.ticketMaxDurationSeconds = seconds ?? undefined
        update()
    }
</script>

<div class="container-max-md">
    <div class="page-summary-bar">
        <h1>global parameters</h1>
    </div>

    <PermissionGate perm="configEdit" message="You have no permission to edit global parameters.">
        <Loadable promise={initPromise}>
        {#if parameters}
            <h4 class="mt-4">Credentials</h4>
            <label
                for="allowOwnCredentialManagement"
                class="d-flex align-items-center"
            >
                <Input
                    id="allowOwnCredentialManagement"
                    class="mb-0 me-2"
                    type="switch"
                    on:change={() => {
                        parameters!.allowOwnCredentialManagement = !parameters!.allowOwnCredentialManagement
                        update()
                    }}
                    checked={parameters.allowOwnCredentialManagement} />
                <div>Allow users to manage their own credentials</div>
            </label>

            <h4 class="mt-4">Traffic</h4>
            <FormGroup>
                <label class="mb-2" for="rateLimitBytesPerSecond">Global bandwidth limit</label>
                <RateLimitInput
                    id="rateLimitBytesPerSecond"
                    bind:value={parameters.rateLimitBytesPerSecond}
                    change={update} />
            </FormGroup>

            <h4 class="mt-4">SSH</h4>
            <!-- svelte-ignore a11y_label_has_associated_control -->
            <label class="mb-2">Allowed authentication methods</label>
            <label
                for="sshClientAuthPublickey"
                class="d-flex align-items-center mb-2"
            >
                <Input
                    id="sshClientAuthPublickey"
                    class="mb-0 me-2"
                    type="switch"
                    on:change={() => {
                        parameters!.sshClientAuthPublickey = !parameters!.sshClientAuthPublickey
                        update()
                    }}
                    checked={parameters.sshClientAuthPublickey} />
                <div>Public key authentication</div>
            </label>
            <label
                for="sshClientAuthPassword"
                class="d-flex align-items-center mb-2"
            >
                <Input
                    id="sshClientAuthPassword"
                    class="mb-0 me-2"
                    type="switch"
                    on:change={() => {
                        parameters!.sshClientAuthPassword = !parameters!.sshClientAuthPassword
                        update()
                    }}
                    checked={parameters.sshClientAuthPassword} />
                <div>Password authentication</div>
            </label>
            <label
                for="sshClientAuthKeyboardInteractive"
                class="d-flex align-items-center"
            >
                <Input
                    id="sshClientAuthKeyboardInteractive"
                    class="mb-0 me-2"
                    type="switch"
                    on:change={() => {
                        parameters!.sshClientAuthKeyboardInteractive = !parameters!.sshClientAuthKeyboardInteractive
                        update()
                    }}
                    checked={parameters.sshClientAuthKeyboardInteractive} />
                <div>Keyboard-interactive authentication (OTP, 2FA prompts)</div>
            </label>
            <InfoBox class="mt-3 mb-3">
                Controls which authentication methods are offered to SSH clients.
                Disabling password authentication can help prevent brute-force attacks.
            </InfoBox>

            <h4 class="mt-4">Self-service tickets</h4>
            <label
                for="ticketSelfServiceEnabled"
                class="d-flex align-items-center mb-2"
            >
                <Input
                    id="ticketSelfServiceEnabled"
                    class="mb-0 me-2"
                    type="switch"
                    on:change={() => {
                        parameters!.ticketSelfServiceEnabled = !parameters!.ticketSelfServiceEnabled
                        update()
                    }}
                    checked={parameters.ticketSelfServiceEnabled} />
                <div>Allow users to request tickets</div>
            </label>
            <InfoBox class="mt-3 mb-3">
                When enabled, authenticated users can request user-tied, time-limited access tickets from their profile page or via the API to a single target.
            </InfoBox>

            {#if parameters.ticketSelfServiceEnabled}
            <label
                for="ticketAutoApproveExistingAccess"
                class="d-flex align-items-center mb-2"
            >
                <Input
                    id="ticketAutoApproveExistingAccess"
                    class="mb-0 me-2"
                    type="switch"
                    on:change={() => {
                        parameters!.ticketAutoApproveExistingAccess = !parameters!.ticketAutoApproveExistingAccess
                        update()
                    }}
                    checked={parameters.ticketAutoApproveExistingAccess} />
                <div>Auto-approve when user already has role-based access</div>
            </label>

            <label
                for="ticketRequireDescription"
                class="d-flex align-items-center mb-2"
            >
                <Input
                    id="ticketRequireDescription"
                    class="mb-0 me-2"
                    type="switch"
                    on:change={() => {
                        parameters!.ticketRequireDescription = !parameters!.ticketRequireDescription
                        update()
                    }}
                    checked={parameters.ticketRequireDescription} />
                <div>Require description on ticket requests</div>
            </label>

            <label
                for="ticketRequestShowAllTargets"
                class="d-flex align-items-center mb-2"
            >
                <Input
                    id="ticketRequestShowAllTargets"
                    class="mb-0 me-2"
                    type="switch"
                    on:change={() => {
                        parameters!.ticketRequestShowAllTargets = !parameters!.ticketRequestShowAllTargets
                        update()
                    }}
                    checked={parameters.ticketRequestShowAllTargets} />
                <div>Show all targets in ticket request form</div>
            </label>
            <InfoBox class="mt-3 mb-3">
                When disabled, users only see targets they already have role-based access to.
            </InfoBox>

            <FormGroup floating label="Default max ticket duration (blank = unlimited)">
                <input
                    type="text"
                    class="form-control"
                    placeholder="e.g. 8h, 30m, 1d"
                    bind:value={durationText}
                    onchange={onDurationChange}
                />
                <small class="form-text text-muted">
                    Global default. Can be overridden per target. Examples: 30m, 8h, 1d, 2h30m.
                </small>
            </FormGroup>

            <FormGroup floating label="Max uses per ticket (blank = unlimited)">
                <input
                    type="number"
                    min="1"
                    class="form-control"
                    value={parameters.ticketMaxUses ?? ''}
                    onchange={e => {
                        const v = parseInt(e.currentTarget.value)
                        parameters!.ticketMaxUses = isNaN(v) ? undefined : v
                        update()
                    }}
                />
            </FormGroup>

            {/if}

            <h4 class="mt-4">HTTP</h4>
            <label
                for="showSessionMenu"
                class="d-flex align-items-center"
            >
                <Input
                    id="showSessionMenu"
                    class="mb-0 me-2"
                    type="switch"
                    on:change={() => {
                        parameters!.showSessionMenu = !parameters!.showSessionMenu
                        update()
                    }}
                    checked={parameters.showSessionMenu} />
                <div>Show session menu</div>
            </label>
            <InfoBox class="mt-3 mb-3">
                Warpgate can inject a session menu into HTTP sessions, allowing users to log out or return back to the home page.
            </InfoBox>

            {#if hasSsoProviders}
            <h4 class="mt-4">Login</h4>
            <label
                for="minimizePasswordLogin"
                class="d-flex align-items-center"
            >
                <Input
                    id="minimizePasswordLogin"
                    class="mb-0 me-2"
                    type="switch"
                    on:change={() => {
                        parameters!.minimizePasswordLogin = !parameters!.minimizePasswordLogin
                        update()
                    }}
                    checked={parameters.minimizePasswordLogin} />
                <div>Minimize password login UI</div>
            </label>
            <InfoBox class="mt-3 mb-3">
                When enabled, the username and password fields are hidden behind a link on the login page, with the focus on the SSO buttons.
            </InfoBox>
            {/if}

            <h4 class="mt-4">Login protection</h4>
            <label
                for="loginProtectionEnabled"
                class="d-flex align-items-center mb-2"
            >
                <Input
                    id="loginProtectionEnabled"
                    class="mb-0 me-2"
                    type="switch"
                    on:change={() => {
                        parameters!.loginProtectionEnabled = !parameters!.loginProtectionEnabled
                        update()
                    }}
                    checked={parameters.loginProtectionEnabled} />
                <div>Enable brute-force protection</div>
            </label>
            <InfoBox class="mt-3 mb-3">
                When enabled, repeated failed login attempts will block the source IP and lock affected user accounts according to the thresholds below.
                Manage blocked IPs and locked users from the <a href="/@warpgate/admin/#/config/login-protection">Login protection</a> page.
            </InfoBox>

            {#if parameters.loginProtectionEnabled}
            <FormGroup floating label="Retention (days)">
                <input
                    id="loginProtectionRetentionDays"
                    type="number"
                    min="1"
                    class="form-control"
                    value={parameters.loginProtectionRetentionDays}
                    onchange={e => {
                        const v = parseInt(e.currentTarget.value)
                        if (!isNaN(v) && v >= 1) {
                            parameters!.loginProtectionRetentionDays = v
                            update()
                        }
                    }}
                />
                <small class="form-text text-muted">
                    How long failed login attempts, blocks, and lockouts are kept in the database.
                </small>
            </FormGroup>

            <h5 class="mt-4">IP rate limiting</h5>
            <InfoBox class="mt-2 mb-3">
                Block source IPs after too many failed attempts within a time window. Subsequent blocks last longer (exponential backoff).
            </InfoBox>

            <FormGroup floating label="Max attempts before block">
                <input
                    id="lpIpMaxAttempts"
                    type="number"
                    min="1"
                    class="form-control"
                    value={parameters.lpIpMaxAttempts}
                    onchange={e => {
                        const v = parseInt(e.currentTarget.value)
                        if (!isNaN(v) && v >= 1) {
                            parameters!.lpIpMaxAttempts = v
                            update()
                        }
                    }}
                />
            </FormGroup>

            <FormGroup floating label="Attempt time window (minutes)">
                <input
                    id="lpIpTimeWindowMinutes"
                    type="number"
                    min="1"
                    class="form-control"
                    value={parameters.lpIpTimeWindowMinutes}
                    onchange={e => {
                        const v = parseInt(e.currentTarget.value)
                        if (!isNaN(v) && v >= 1) {
                            parameters!.lpIpTimeWindowMinutes = v
                            update()
                        }
                    }}
                />
            </FormGroup>

            <FormGroup floating label="Base block duration (minutes)">
                <input
                    id="lpIpBaseBlockDurationMinutes"
                    type="number"
                    min="1"
                    class="form-control"
                    value={parameters.lpIpBaseBlockDurationMinutes}
                    onchange={e => {
                        const v = parseInt(e.currentTarget.value)
                        if (!isNaN(v) && v >= 1) {
                            parameters!.lpIpBaseBlockDurationMinutes = v
                            update()
                        }
                    }}
                />
            </FormGroup>

            <FormGroup floating label="Block duration multiplier">
                <input
                    id="lpIpBlockDurationMultiplier"
                    type="number"
                    min="1"
                    step="0.1"
                    class="form-control"
                    value={parameters.lpIpBlockDurationMultiplier}
                    onchange={e => {
                        const v = parseFloat(e.currentTarget.value)
                        if (!isNaN(v) && v >= 1) {
                            parameters!.lpIpBlockDurationMultiplier = v
                            update()
                        }
                    }}
                />
                <small class="form-text text-muted">
                    Each repeat block multiplies the previous duration by this factor (e.g. 2.0 doubles each time).
                </small>
            </FormGroup>

            <FormGroup floating label="Max block duration (hours)">
                <input
                    id="lpIpMaxBlockDurationHours"
                    type="number"
                    min="1"
                    class="form-control"
                    value={parameters.lpIpMaxBlockDurationHours}
                    onchange={e => {
                        const v = parseInt(e.currentTarget.value)
                        if (!isNaN(v) && v >= 1) {
                            parameters!.lpIpMaxBlockDurationHours = v
                            update()
                        }
                    }}
                />
                <small class="form-text text-muted">
                    Cap on exponential backoff. Blocks will never exceed this duration.
                </small>
            </FormGroup>

            <FormGroup floating label="Cooldown reset (hours)">
                <input
                    id="lpIpCooldownResetHours"
                    type="number"
                    min="1"
                    class="form-control"
                    value={parameters.lpIpCooldownResetHours}
                    onchange={e => {
                        const v = parseInt(e.currentTarget.value)
                        if (!isNaN(v) && v >= 1) {
                            parameters!.lpIpCooldownResetHours = v
                            update()
                        }
                    }}
                />
                <small class="form-text text-muted">
                    After this period without failed attempts, the block-count for the IP is reset.
                </small>
            </FormGroup>

            <FormGroup floating label="Custom blocked-IP message (optional)">
                <input
                    id="lpIpBlockedMessage"
                    type="text"
                    class="form-control"
                    placeholder="Default: Your IP has been temporarily blocked due to too many failed login attempts."
                    value={parameters.lpIpBlockedMessage ?? ''}
                    onchange={e => {
                        const v = e.currentTarget.value.trim()
                        parameters!.lpIpBlockedMessage = v === '' ? undefined : v
                        update()
                    }}
                />
            </FormGroup>

            <h5 class="mt-4">User lockout</h5>
            <InfoBox class="mt-2 mb-3">
                Lock specific user accounts after repeated failed attempts targeting them, independent of source IP.
            </InfoBox>

            <FormGroup floating label="Max attempts before lockout">
                <input
                    id="lpUserMaxAttempts"
                    type="number"
                    min="1"
                    class="form-control"
                    value={parameters.lpUserMaxAttempts}
                    onchange={e => {
                        const v = parseInt(e.currentTarget.value)
                        if (!isNaN(v) && v >= 1) {
                            parameters!.lpUserMaxAttempts = v
                            update()
                        }
                    }}
                />
            </FormGroup>

            <FormGroup floating label="Attempt time window (minutes)">
                <input
                    id="lpUserTimeWindowMinutes"
                    type="number"
                    min="1"
                    class="form-control"
                    value={parameters.lpUserTimeWindowMinutes}
                    onchange={e => {
                        const v = parseInt(e.currentTarget.value)
                        if (!isNaN(v) && v >= 1) {
                            parameters!.lpUserTimeWindowMinutes = v
                            update()
                        }
                    }}
                />
            </FormGroup>

            <label
                for="lpUserAutoUnlock"
                class="d-flex align-items-center mb-2 mt-2"
            >
                <Input
                    id="lpUserAutoUnlock"
                    class="mb-0 me-2"
                    type="switch"
                    on:change={() => {
                        parameters!.lpUserAutoUnlock = !parameters!.lpUserAutoUnlock
                        update()
                    }}
                    checked={parameters.lpUserAutoUnlock} />
                <div>Auto-unlock after lockout duration</div>
            </label>
            <InfoBox class="mt-2 mb-3">
                When off, locked users stay locked until an admin manually unlocks them.
            </InfoBox>

            {#if parameters.lpUserAutoUnlock}
            <FormGroup floating label="Lockout duration (minutes)">
                <input
                    id="lpUserLockoutDurationMinutes"
                    type="number"
                    min="1"
                    class="form-control"
                    value={parameters.lpUserLockoutDurationMinutes}
                    onchange={e => {
                        const v = parseInt(e.currentTarget.value)
                        if (!isNaN(v) && v >= 1) {
                            parameters!.lpUserLockoutDurationMinutes = v
                            update()
                        }
                    }}
                />
            </FormGroup>
            {/if}

            <FormGroup floating label="Custom locked-user message (optional)">
                <input
                    id="lpUserLockedMessage"
                    type="text"
                    class="form-control"
                    placeholder="Default: This account has been temporarily locked due to too many failed login attempts."
                    value={parameters.lpUserLockedMessage ?? ''}
                    onchange={e => {
                        const v = e.currentTarget.value.trim()
                        parameters!.lpUserLockedMessage = v === '' ? undefined : v
                        update()
                    }}
                />
            </FormGroup>
            {/if}
        {/if}
        </Loadable>
    </PermissionGate>
</div>
