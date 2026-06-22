<script lang="ts">
    import { FormGroup, Input } from '@sveltestrap/sveltestrap'
    import { link } from 'svelte-spa-router'
    import { api, TargetClickAction, type ParameterValues } from 'admin/lib/api'
    import { api as gatewayApi } from 'gateway/lib/api'
    import Loadable from 'common/Loadable.svelte'
    import RateLimitInput from 'common/RateLimitInput.svelte'
    import InfoBox from 'common/InfoBox.svelte'
    import PermissionGate from 'admin/lib/PermissionGate.svelte'
    import Alert from 'common/sveltestrap-s5-ports/Alert.svelte'
    import { humantimeDuration } from 'common/duration'
    import { reloadServerInfo } from 'gateway/lib/store'
    import { stringifyError } from 'common/errors'
    import SectionedForm from 'admin/lib/SectionedForm.svelte'
    import Section from 'admin/lib/Section.svelte'

    let parameters: ParameterValues | undefined = $state()
    let hasSsoProviders = $state(false)
    let updateError: string | undefined = $state()
    let saveTimer: ReturnType<typeof setTimeout> | undefined

    // Cross-field validation: initial block must not exceed the max cap.
    const lpCapWarning = $derived.by(() => {
        if (!parameters?.loginProtectionEnabled) return undefined
        const initialMin = parameters.lpIpBaseBlockDurationMinutes
        const maxMin = parameters.lpIpMaxBlockDurationHours * 60
        return initialMin > maxMin
            ? `Initial block (${initialMin} min) exceeds the max cap (${maxMin} min). The initial duration will be clamped to the maximum.`
            : undefined
    })

    const initPromise = init()

    async function init () {
        parameters = await api.getParameters({})
        const ssoProviders = await gatewayApi.getSsoProviders()
        hasSsoProviders = ssoProviders.length > 0
    }

    async function update() {
        updateError = undefined
        try {
            await api.updateParameters({
                parameterUpdate: parameters!,
            })
            await reloadServerInfo()
        } catch (err) {
            updateError = await stringifyError(err)
        }
    }

    // Debounced save for numeric fields — coalesces rapid changes into one PUT.
    function scheduleUpdate() {
        clearTimeout(saveTimer)
        saveTimer = setTimeout(update, 400)
    }
</script>

<div class="container-max-md">
    <div class="page-summary-bar">
        <h1>global parameters</h1>
    </div>

    <PermissionGate perm="configEdit" message="You have no permission to edit global parameters.">
        {#if updateError}
            <Alert color="danger" dismissible onclose={() => { updateError = undefined }}>{updateError}</Alert>
        {/if}
        <Loadable promise={initPromise}>
        {#if parameters}
            <SectionedForm>
                <Section id="credentials" title="Credentials">
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
                </Section>

                <Section id="password-policy" title="Password policy">
                    <FormGroup floating label="Minimum length (0 = no requirement)">
                        <input
                            type="number"
                            min="0"
                            class="form-control"
                            value={parameters.passwordPolicy.minLength}
                            onchange={e => {
                                const v = parseInt(e.currentTarget.value)
                                parameters!.passwordPolicy.minLength = isNaN(v) ? 0 : Math.max(0, v)
                                update()
                            }}
                        />
                    </FormGroup>
                    <label
                        for="requireUppercase"
                        class="d-flex align-items-center mb-2"
                    >
                        <Input
                            id="requireUppercase"
                            class="mb-0 me-2"
                            type="switch"
                            on:change={() => {
                                parameters!.passwordPolicy.requireUppercase = !parameters!.passwordPolicy.requireUppercase
                                update()
                            }}
                            checked={parameters.passwordPolicy.requireUppercase} />
                        <div>Require uppercase letter</div>
                    </label>
                    <label
                        for="requireLowercase"
                        class="d-flex align-items-center mb-2"
                    >
                        <Input
                            id="requireLowercase"
                            class="mb-0 me-2"
                            type="switch"
                            on:change={() => {
                                parameters!.passwordPolicy.requireLowercase = !parameters!.passwordPolicy.requireLowercase
                                update()
                            }}
                            checked={parameters.passwordPolicy.requireLowercase} />
                        <div>Require lowercase letter</div>
                    </label>
                    <label
                        for="requireDigits"
                        class="d-flex align-items-center mb-2"
                    >
                        <Input
                            id="requireDigits"
                            class="mb-0 me-2"
                            type="switch"
                            on:change={() => {
                                parameters!.passwordPolicy.requireDigits = !parameters!.passwordPolicy.requireDigits
                                update()
                            }}
                            checked={parameters.passwordPolicy.requireDigits} />
                        <div>Require digit</div>
                    </label>
                    <label
                        for="requireSpecial"
                        class="d-flex align-items-center"
                    >
                        <Input
                            id="requireSpecial"
                            class="mb-0 me-2"
                            type="switch"
                            on:change={() => {
                                parameters!.passwordPolicy.requireSpecial = !parameters!.passwordPolicy.requireSpecial
                                update()
                            }}
                            checked={parameters.passwordPolicy.requireSpecial} />
                        <div>Require special character</div>
                    </label>
                </Section>

                <Section id="traffic" title="Traffic">
                    <FormGroup>
                        <label class="mb-2" for="rateLimitBytesPerSecond">Global bandwidth limit</label>
                        <RateLimitInput
                            id="rateLimitBytesPerSecond"
                            bind:value={parameters.rateLimitBytesPerSecond}
                            change={update} />
                    </FormGroup>
                </Section>

                <Section id="ssh" title="SSH">
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

                    <div class="mt-3"></div>

                    <label
                        for="recordScp"
                        class="d-flex align-items-center mt-2"
                    >
                        <Input
                            id="recordScp"
                            class="mb-0 me-2"
                            type="switch"
                            on:change={() => {
                                parameters!.recordScp = !parameters!.recordScp
                                update()
                            }}
                            checked={parameters.recordScp} />
                        <div>Record legacy SCP transfers</div>
                    </label>
                    <InfoBox class="mt-3 mb-3">
                        Legacy SCP works over an exec channel and would be normally recorded like any other command. Disable to prevent SCP recordings from wasting storage space.
                    </InfoBox>
                </Section>

                <Section id="tickets" bodyTitle="Self-service tickets" title="Tickets">
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
                            use:humantimeDuration={{ seconds: parameters.ticketMaxDurationSeconds, onChange: v => { parameters!.ticketMaxDurationSeconds = v; update() } }}
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
                </Section>

                <Section id="api-tokens" title="API tokens">
                    <FormGroup floating label="Maximum API token duration (blank = unlimited)">
                        <input
                            type="text"
                            class="form-control"
                            placeholder="e.g. 8h, 30m, 1d"
                            use:humantimeDuration={{ seconds: parameters.maxApiTokenDurationSeconds, onChange: v => { parameters!.maxApiTokenDurationSeconds = v; update() } }}
                        />
                    </FormGroup>
                </Section>

                <Section id="ui" title="UI">
                    <FormGroup floating label="SSH target click action">
                        <select
                            id="targetClickAction"
                            class="form-select"
                            value={parameters.targetClickAction ?? 'Connect'}
                            onchange={e => {
                                parameters!.targetClickAction = e.currentTarget.value as TargetClickAction
                                update()
                            }}
                        >
                            <option value="Connect">Open web terminal</option>
                            <option value="ShowInstructions">Show connection instructions</option>
                        </select>
                    </FormGroup>

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
                        <div>Show HTTP session menu</div>
                    </label>
                    <InfoBox class="mt-3 mb-3">
                        Warpgate can inject a session menu into HTTP sessions, allowing users to log out or return back to the home page.
                    </InfoBox>
                </Section>

                {#if hasSsoProviders}
                <Section id="login" title="Login">
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
                </Section>
                {/if}

                <Section id="login-protection" title="Login protection">
                    <!-- Master toggle -->
                    <label
                        for="loginProtectionEnabled"
                        class="d-flex align-items-center"
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
                    <InfoBox class="mt-2 mb-3">
                        Rate-limits IPs and locks accounts after repeated failed logins. When disabled, all settings below are preserved but not enforced.
                    </InfoBox>

                    {#if lpCapWarning}
                        <Alert color="warning" class="mb-2">{lpCapWarning}</Alert>
                    {/if}

                    <!-- All policy settings — dims when disabled -->
                    <div class:lp-disabled={!parameters.loginProtectionEnabled}>

                        <p class="lp-group-title">IP rate-limit</p>
                        <div class="row g-2 mb-2">
                            <div class="col-sm-6">
                                <FormGroup floating label="Max failures before IP block">
                                    <input type="number" min="1" max="1000" class="form-control"
                                        disabled={!parameters.loginProtectionEnabled}
                                        value={parameters.lpIpMaxAttempts}
                                        onchange={e => { const v = parseInt(e.currentTarget.value); if (!isNaN(v) && v >= 1) { parameters!.lpIpMaxAttempts = v; scheduleUpdate() } else { e.currentTarget.value = String(parameters!.lpIpMaxAttempts) } }} />
                                </FormGroup>
                            </div>
                            <div class="col-sm-6">
                                <FormGroup floating label="Failure window (minutes)">
                                    <input type="number" min="1" max="1440" class="form-control"
                                        disabled={!parameters.loginProtectionEnabled}
                                        value={parameters.lpIpTimeWindowMinutes}
                                        onchange={e => { const v = parseInt(e.currentTarget.value); if (!isNaN(v) && v >= 1) { parameters!.lpIpTimeWindowMinutes = v; scheduleUpdate() } else { e.currentTarget.value = String(parameters!.lpIpTimeWindowMinutes) } }} />
                                </FormGroup>
                            </div>
                            <div class="col-6 col-sm-3">
                                <FormGroup floating label="Initial block (min)">
                                    <input type="number" min="1" max="1440" class="form-control"
                                        disabled={!parameters.loginProtectionEnabled}
                                        value={parameters.lpIpBaseBlockDurationMinutes}
                                        onchange={e => { const v = parseInt(e.currentTarget.value); if (!isNaN(v) && v >= 1) { parameters!.lpIpBaseBlockDurationMinutes = v; scheduleUpdate() } else { e.currentTarget.value = String(parameters!.lpIpBaseBlockDurationMinutes) } }} />
                                </FormGroup>
                            </div>
                            <div class="col-6 col-sm-3">
                                <FormGroup floating label="Backoff multiplier">
                                    <input type="number" min="1.0" max="10" step="0.5" class="form-control"
                                        disabled={!parameters.loginProtectionEnabled}
                                        value={parameters.lpIpBlockDurationMultiplier}
                                        onchange={e => { const v = parseFloat(e.currentTarget.value); if (!isNaN(v) && v >= 1) { parameters!.lpIpBlockDurationMultiplier = v; scheduleUpdate() } else { e.currentTarget.value = String(parameters!.lpIpBlockDurationMultiplier) } }} />
                                </FormGroup>
                            </div>
                            <div class="col-6 col-sm-3">
                                <FormGroup floating label="Max block (hours)">
                                    <input type="number" min="1" max="720" class="form-control"
                                        disabled={!parameters.loginProtectionEnabled}
                                        value={parameters.lpIpMaxBlockDurationHours}
                                        onchange={e => { const v = parseInt(e.currentTarget.value); if (!isNaN(v) && v >= 1) { parameters!.lpIpMaxBlockDurationHours = v; scheduleUpdate() } else { e.currentTarget.value = String(parameters!.lpIpMaxBlockDurationHours) } }} />
                                </FormGroup>
                            </div>
                            <div class="col-6 col-sm-3">
                                <FormGroup floating label="Cooldown reset (hours)">
                                    <input type="number" min="1" max="720" class="form-control"
                                        disabled={!parameters.loginProtectionEnabled}
                                        value={parameters.lpIpCooldownResetHours}
                                        onchange={e => { const v = parseInt(e.currentTarget.value); if (!isNaN(v) && v >= 1) { parameters!.lpIpCooldownResetHours = v; scheduleUpdate() } else { e.currentTarget.value = String(parameters!.lpIpCooldownResetHours) } }} />
                                </FormGroup>
                            </div>
                        </div>
                        <InfoBox class="mb-3">
                            Each block is <strong>multiplier × the previous block duration</strong>, capped at the maximum. The repeat count resets only after the cooldown period of <em>clean</em> activity — not when a block expires.
                        </InfoBox>

                        <p class="lp-group-title">User lockout</p>
                        <div class="row g-2 mb-2">
                            <div class="col-sm-6">
                                <FormGroup floating label="Max failures before lockout">
                                    <input type="number" min="1" max="1000" class="form-control"
                                        disabled={!parameters.loginProtectionEnabled}
                                        value={parameters.lpUserMaxAttempts}
                                        onchange={e => { const v = parseInt(e.currentTarget.value); if (!isNaN(v) && v >= 1) { parameters!.lpUserMaxAttempts = v; scheduleUpdate() } else { e.currentTarget.value = String(parameters!.lpUserMaxAttempts) } }} />
                                </FormGroup>
                            </div>
                            <div class="col-sm-6">
                                <FormGroup floating label="Failure window (minutes)">
                                    <input type="number" min="1" max="1440" class="form-control"
                                        disabled={!parameters.loginProtectionEnabled}
                                        value={parameters.lpUserTimeWindowMinutes}
                                        onchange={e => { const v = parseInt(e.currentTarget.value); if (!isNaN(v) && v >= 1) { parameters!.lpUserTimeWindowMinutes = v; scheduleUpdate() } else { e.currentTarget.value = String(parameters!.lpUserTimeWindowMinutes) } }} />
                                </FormGroup>
                            </div>
                        </div>
                        <label
                            for="lpUserAutoUnlock"
                            class="d-flex align-items-center mb-2"
                        >
                            <Input
                                id="lpUserAutoUnlock"
                                class="mb-0 me-2"
                                type="switch"
                                disabled={!parameters.loginProtectionEnabled}
                                on:change={() => { parameters!.lpUserAutoUnlock = !parameters!.lpUserAutoUnlock; update() }}
                                checked={parameters.lpUserAutoUnlock} />
                            <div>Auto-unlock after timeout</div>
                        </label>
                        {#if parameters.lpUserAutoUnlock}
                            <FormGroup floating label="Auto-unlock delay (minutes)" class="mb-2">
                                <input type="number" min="1" max="10080" class="form-control"
                                    disabled={!parameters.loginProtectionEnabled}
                                    value={parameters.lpUserLockoutDurationMinutes}
                                    onchange={e => { const v = parseInt(e.currentTarget.value); if (!isNaN(v) && v >= 1) { parameters!.lpUserLockoutDurationMinutes = v; scheduleUpdate() } else { e.currentTarget.value = String(parameters!.lpUserLockoutDurationMinutes) } }} />
                            </FormGroup>
                        {/if}

                        <p class="lp-group-title">Data retention</p>
                        <FormGroup floating label="Keep records for (days)" class="mb-3">
                            <input type="number" min="1" max="3650" class="form-control"
                                disabled={!parameters.loginProtectionEnabled}
                                value={parameters.loginProtectionRetentionDays}
                                onchange={e => { const v = parseInt(e.currentTarget.value); if (!isNaN(v) && v >= 1) { parameters!.loginProtectionRetentionDays = v; scheduleUpdate() } else { e.currentTarget.value = String(parameters!.loginProtectionRetentionDays) } }} />
                        </FormGroup>

                        <p class="lp-group-title">Custom messages</p>
                        <FormGroup floating label="Blocked-IP message (optional)" class="mb-2">
                            <input id="lpIpBlockedMessage" type="text" class="form-control"
                                placeholder="IP temporarily blocked due to failed logins"
                                disabled={!parameters.loginProtectionEnabled}
                                value={parameters.lpIpBlockedMessage ?? ''}
                                oninput={e => { const v = e.currentTarget.value.trim(); parameters!.lpIpBlockedMessage = v === '' ? undefined : v; scheduleUpdate() }} />
                        </FormGroup>
                        <FormGroup floating label="Locked-user message (optional)" class="mb-2">
                            <input id="lpUserLockedMessage" type="text" class="form-control"
                                placeholder="Account temporarily locked due to failed logins"
                                disabled={!parameters.loginProtectionEnabled}
                                value={parameters.lpUserLockedMessage ?? ''}
                                oninput={e => { const v = e.currentTarget.value.trim(); parameters!.lpUserLockedMessage = v === '' ? undefined : v; scheduleUpdate() }} />
                        </FormGroup>
                        <InfoBox class="mb-1">
                            Returned as plain text in the HTTP login response and SSH error banner. Leave empty for the default message.
                        </InfoBox>
                    </div>

                    <div class="lp-foot text-muted mt-2">
                        Manage active blocks &amp; lockouts on the <a href="/config/login-protection" use:link>Login protection</a> page.
                    </div>
                </Section>
            </SectionedForm>
        {/if}
        </Loadable>
    </PermissionGate>
</div>

<style>
    /* Dims the entire policy block when LP is disabled */
    .lp-disabled {
        opacity: .45;
        pointer-events: none;
        user-select: none;
        transition: opacity .15s;
    }

    /* Subsection headings inside the LP section */
    .lp-group-title {
        font-size: .75rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: .06em;
        color: var(--bs-secondary-color);
        margin: 1rem 0 .5rem;
    }
    .lp-group-title:first-child {
        margin-top: .25rem;
    }

    /* Footer link */
    .lp-foot {
        font-size: .8rem;
    }
</style>
