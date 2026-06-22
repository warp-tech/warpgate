<script lang="ts">
    import { FormGroup, Input } from '@sveltestrap/sveltestrap'
    import { link } from 'svelte-spa-router'
    import { api, TargetClickAction, type ParameterValues } from 'admin/lib/api'
    import { api as gatewayApi } from 'gateway/lib/api'
    import Loadable from 'common/Loadable.svelte'
    import RateLimitInput from 'common/RateLimitInput.svelte'
    import InfoBox from 'common/InfoBox.svelte'
    import PermissionGate from 'admin/lib/PermissionGate.svelte'
    import { humantimeDuration } from 'common/duration'
    import { reloadServerInfo } from 'gateway/lib/store'
    import SectionedForm from 'admin/lib/SectionedForm.svelte'
    import Section from 'admin/lib/Section.svelte'

    let parameters: ParameterValues | undefined = $state()
    let hasSsoProviders = $state(false)
    const initPromise = init()

    async function init () {
        parameters = await api.getParameters({})
        const ssoProviders = await gatewayApi.getSsoProviders()
        hasSsoProviders = ssoProviders.length > 0
    }

    async function update() {
        await api.updateParameters({
            parameterUpdate: parameters!,
        })
        await reloadServerInfo()
    }
</script>

<div class="container-max-md">
    <div class="page-summary-bar">
        <h1>global parameters</h1>
    </div>

    <PermissionGate perm="configEdit" message="You have no permission to edit global parameters.">
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
                        <div>Brute-force protection (IP rate-limit + user lockout)</div>
                    </label>

                    {#if parameters.loginProtectionEnabled}
                    <div class="lp-block mt-2 mb-2">
                        <div class="lp-row">
                            <span class="lp-label" aria-hidden="true">IP rate-limit</span>
                            <span class="lp-sentence" role="group" aria-label="IP rate-limit policy">
                                Block after
                                <input type="number" min="1" max="1000" class="form-control form-control-sm lp-num"
                                    aria-label="Max failed attempts from one IP before blocking"
                                    value={parameters.lpIpMaxAttempts}
                                    onchange={e => { const v = parseInt(e.currentTarget.value); if (!isNaN(v) && v >= 1) { parameters!.lpIpMaxAttempts = v; update() } else { e.currentTarget.value = String(parameters!.lpIpMaxAttempts) } }} />
                                failed attempts in
                                <input type="number" min="1" max="1440" class="form-control form-control-sm lp-num"
                                    aria-label="Time window for counting failed attempts, in minutes"
                                    value={parameters.lpIpTimeWindowMinutes}
                                    onchange={e => { const v = parseInt(e.currentTarget.value); if (!isNaN(v) && v >= 1) { parameters!.lpIpTimeWindowMinutes = v; update() } else { e.currentTarget.value = String(parameters!.lpIpTimeWindowMinutes) } }} />
                                min for
                                <input type="number" min="1" max="1440" class="form-control form-control-sm lp-num"
                                    aria-label="Initial block duration in minutes"
                                    value={parameters.lpIpBaseBlockDurationMinutes}
                                    onchange={e => { const v = parseInt(e.currentTarget.value); if (!isNaN(v) && v >= 1) { parameters!.lpIpBaseBlockDurationMinutes = v; update() } else { e.currentTarget.value = String(parameters!.lpIpBaseBlockDurationMinutes) } }} />
                                min, ×
                                <input type="number" min="1" max="10" step="0.1" class="form-control form-control-sm lp-num lp-num-wide"
                                    aria-label="Multiplier applied to the block duration on each repeat offense"
                                    title="Each repeat block multiplies the previous duration by this factor (e.g. 2.0 doubles each time)"
                                    value={parameters.lpIpBlockDurationMultiplier}
                                    onchange={e => { const v = parseFloat(e.currentTarget.value); if (!isNaN(v) && v >= 1) { parameters!.lpIpBlockDurationMultiplier = v; update() } else { e.currentTarget.value = String(parameters!.lpIpBlockDurationMultiplier) } }} />
                                on repeat, capped at
                                <input type="number" min="1" max="720" class="form-control form-control-sm lp-num"
                                    aria-label="Maximum block duration in hours"
                                    value={parameters.lpIpMaxBlockDurationHours}
                                    onchange={e => { const v = parseInt(e.currentTarget.value); if (!isNaN(v) && v >= 1) { parameters!.lpIpMaxBlockDurationHours = v; update() } else { e.currentTarget.value = String(parameters!.lpIpMaxBlockDurationHours) } }} />
                                h, reset after
                                <input type="number" min="1" max="720" class="form-control form-control-sm lp-num"
                                    aria-label="Hours of inactivity after which the repeat-offense counter resets"
                                    value={parameters.lpIpCooldownResetHours}
                                    onchange={e => { const v = parseInt(e.currentTarget.value); if (!isNaN(v) && v >= 1) { parameters!.lpIpCooldownResetHours = v; update() } else { e.currentTarget.value = String(parameters!.lpIpCooldownResetHours) } }} />
                                h idle.
                            </span>
                        </div>
                        <div class="lp-row">
                            <span class="lp-label" aria-hidden="true">User lockout</span>
                            <span class="lp-sentence" role="group" aria-label="User lockout policy">
                                Lock account after
                                <input type="number" min="1" max="1000" class="form-control form-control-sm lp-num"
                                    aria-label="Max failed attempts against a single user before locking the account"
                                    value={parameters.lpUserMaxAttempts}
                                    onchange={e => { const v = parseInt(e.currentTarget.value); if (!isNaN(v) && v >= 1) { parameters!.lpUserMaxAttempts = v; update() } else { e.currentTarget.value = String(parameters!.lpUserMaxAttempts) } }} />
                                failed attempts in
                                <input type="number" min="1" max="1440" class="form-control form-control-sm lp-num"
                                    aria-label="Time window for counting failed attempts against a single user, in minutes"
                                    value={parameters.lpUserTimeWindowMinutes}
                                    onchange={e => { const v = parseInt(e.currentTarget.value); if (!isNaN(v) && v >= 1) { parameters!.lpUserTimeWindowMinutes = v; update() } else { e.currentTarget.value = String(parameters!.lpUserTimeWindowMinutes) } }} />
                                min.
                                <label class="lp-inline-switch" for="lpUserAutoUnlock">
                                    <Input
                                        id="lpUserAutoUnlock"
                                        class="mb-0 me-1"
                                        type="switch"
                                        on:change={() => { parameters!.lpUserAutoUnlock = !parameters!.lpUserAutoUnlock; update() }}
                                        checked={parameters.lpUserAutoUnlock} />
                                    Auto-unlock
                                </label>
                                {#if parameters.lpUserAutoUnlock}
                                after
                                <input type="number" min="1" max="10080" class="form-control form-control-sm lp-num"
                                    aria-label="Auto-unlock delay in minutes"
                                    value={parameters.lpUserLockoutDurationMinutes}
                                    onchange={e => { const v = parseInt(e.currentTarget.value); if (!isNaN(v) && v >= 1) { parameters!.lpUserLockoutDurationMinutes = v; update() } else { e.currentTarget.value = String(parameters!.lpUserLockoutDurationMinutes) } }} />
                                min.
                                {/if}
                            </span>
                        </div>
                        <div class="lp-row">
                            <span class="lp-label" aria-hidden="true">Retention</span>
                            <span class="lp-sentence" role="group" aria-label="History retention policy">
                                Keep blocks, lockouts, and attempt history for
                                <input type="number" min="1" max="3650" class="form-control form-control-sm lp-num"
                                    aria-label="Days to retain failed-attempt, block, and lockout history"
                                    value={parameters.loginProtectionRetentionDays}
                                    onchange={e => { const v = parseInt(e.currentTarget.value); if (!isNaN(v) && v >= 1) { parameters!.loginProtectionRetentionDays = v; update() } else { e.currentTarget.value = String(parameters!.loginProtectionRetentionDays) } }} />
                                days.
                            </span>
                        </div>
                        <div class="lp-row lp-row-msg">
                            <label class="lp-label" for="lpIpBlockedMessage">Blocked-IP message</label>
                            <input id="lpIpBlockedMessage" type="text" class="form-control form-control-sm lp-msg"
                                placeholder="IP temporarily blocked due to failed logins"
                                value={parameters.lpIpBlockedMessage ?? ''}
                                onchange={e => { const v = e.currentTarget.value.trim(); parameters!.lpIpBlockedMessage = v === '' ? undefined : v; update() }} />
                        </div>
                        <div class="lp-row lp-row-msg">
                            <label class="lp-label" for="lpUserLockedMessage">Locked-user message</label>
                            <input id="lpUserLockedMessage" type="text" class="form-control form-control-sm lp-msg"
                                placeholder="Account temporarily locked due to failed logins"
                                value={parameters.lpUserLockedMessage ?? ''}
                                onchange={e => { const v = e.currentTarget.value.trim(); parameters!.lpUserLockedMessage = v === '' ? undefined : v; update() }} />
                        </div>
                        <div class="lp-foot text-muted">
                            Manage active blocks &amp; lockouts on the <a href="/config/login-protection" use:link>Login protection</a> page.
                        </div>
                    </div>
                    {/if}
                </Section>
            </SectionedForm>
        {/if}
        </Loadable>
    </PermissionGate>
</div>

<style>
    .lp-block {
        display: flex;
        flex-direction: column;
        gap: .4rem;
        padding: .75rem .9rem;
        border-radius: .375rem;
        background: rgba(127, 127, 127, .06);
    }
    .lp-row {
        display: flex;
        flex-wrap: wrap;
        align-items: baseline;
        gap: .35rem .75rem;
        line-height: 1.9;
    }
    .lp-row-msg {
        align-items: center;
    }
    .lp-label {
        flex: 0 0 9rem;
        font-size: .8rem;
        text-transform: uppercase;
        letter-spacing: .04em;
        color: var(--bs-secondary-color, #888);
        line-height: 1.6;
        margin: 0;
    }
    .lp-sentence {
        flex: 1 1 0;
        min-width: 0;
        display: inline-flex;
        flex-wrap: wrap;
        align-items: baseline;
        gap: .25rem .35rem;
    }
    .lp-num {
        width: 4.5rem;
        text-align: right;
        display: inline-block;
        padding-inline: .4rem;
    }
    .lp-num-wide { width: 5rem; }
    .lp-num:invalid {
        border-color: var(--bs-danger, #dc3545);
    }
    .lp-msg {
        flex: 1 1 0;
        min-width: 0;
    }
    .lp-inline-switch {
        display: inline-flex;
        align-items: center;
        gap: .25rem;
        margin: 0;
        padding-left: .5rem;
    }
    .lp-foot {
        font-size: .8rem;
        margin-top: .15rem;
    }
    @media (max-width: 575.98px) {
        .lp-row {
            flex-direction: column;
            align-items: flex-start;
            gap: .15rem;
        }
        .lp-label {
            flex: 0 0 auto;
        }
        .lp-sentence {
            line-height: 1.7;
        }
    }
</style>
