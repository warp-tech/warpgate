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
    import AsyncButton from 'common/AsyncButton.svelte'
    import { humantimeDuration } from 'common/duration'
    import { reloadServerInfo } from 'gateway/lib/store'
    import { stringifyError } from 'common/errors'
    import SectionedForm from 'admin/lib/SectionedForm.svelte'
    import Section from 'admin/lib/Section.svelte'
    import StickyActionBar from 'common/StickyActionBar.svelte'

    let parameters: ParameterValues | undefined = $state()
    let hasSsoProviders = $state(false)
    let updateError: string | undefined = $state()
    let formEl: HTMLFormElement | undefined = $state()
    let formValid = $state(true)

    // Cross-field hint: initial block longer than the cap will be clamped.
    const lpCapWarning = $derived.by(() => {
        if (!parameters?.loginProtectionEnabled) { return undefined }
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

    function refreshValidity () {
        formValid = formEl?.checkValidity() ?? false
    }

    $effect(() => {
        // Validate once the form has rendered with loaded values.
        if (formEl && parameters) {
            refreshValidity()
        }
    })

    async function save () {
        updateError = undefined
        try {
            await api.updateParameters({ parameterUpdate: parameters! })
            await reloadServerInfo()
        } catch (err) {
            updateError = await stringifyError(err)
        }
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
            <form
                bind:this={formEl}
                oninput={refreshValidity}
                onchange={refreshValidity}
                onsubmit={e => { e.preventDefault(); save() }}
            >
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
                            bind:checked={parameters.allowOwnCredentialManagement} />
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
                            bind:checked={parameters.passwordPolicy.requireUppercase} />
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
                            bind:checked={parameters.passwordPolicy.requireLowercase} />
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
                            bind:checked={parameters.passwordPolicy.requireDigits} />
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
                            bind:checked={parameters.passwordPolicy.requireSpecial} />
                        <div>Require special character</div>
                    </label>
                </Section>

                <Section id="traffic" title="Traffic">
                    <FormGroup>
                        <label class="mb-2" for="rateLimitBytesPerSecond">Global bandwidth limit</label>
                        <RateLimitInput
                            id="rateLimitBytesPerSecond"
                            bind:value={parameters.rateLimitBytesPerSecond}
                            change={refreshValidity} />
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
                            bind:checked={parameters.sshClientAuthPublickey} />
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
                            bind:checked={parameters.sshClientAuthPassword}
                        />
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
                            bind:checked={parameters.sshClientAuthKeyboardInteractive} />
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
                            bind:checked={parameters.recordScp} />
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
                            bind:checked={parameters.ticketSelfServiceEnabled} />
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
                            bind:checked={parameters.ticketAutoApproveExistingAccess} />
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
                            bind:checked={parameters.ticketRequireDescription} />
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
                            bind:checked={parameters.ticketRequestShowAllTargets} />
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
                            use:humantimeDuration={{ seconds: parameters.ticketMaxDurationSeconds, onChange: v => { parameters!.ticketMaxDurationSeconds = v } }}
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
                            use:humantimeDuration={{ seconds: parameters.maxApiTokenDurationSeconds, onChange: v => { parameters!.maxApiTokenDurationSeconds = v } }}
                        />
                    </FormGroup>
                </Section>

                <Section id="ui" title="UI">
                    <FormGroup floating label="SSH target click action">
                        <select
                            id="targetClickAction"
                            class="form-select"
                            value={parameters.targetClickAction ?? 'Connect'}
                            onchange={e => parameters!.targetClickAction = e.currentTarget.value as TargetClickAction}
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
                            bind:checked={parameters.showSessionMenu} />
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
                            bind:checked={parameters.minimizePasswordLogin} />
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
                            bind:checked={parameters.loginProtectionEnabled} />
                        <div>Enable brute-force protection</div>
                    </label>
                    <InfoBox class="mt-2 mb-3">
                        Rate-limits IPs and locks accounts after repeated failed logins. When disabled, all settings below are preserved but not enforced.
                    </InfoBox>

                    {#if lpCapWarning}
                        <Alert color="warning" class="mb-2">{lpCapWarning}</Alert>
                    {/if}

                    {#if parameters.loginProtectionEnabled}
                        <p class="lp-group-title">IP rate-limit</p>
                        <div class="row g-2 mb-2">
                            <div class="col-sm-6">
                                <FormGroup floating label="Max failures before IP block">
                                    <input type="number" min="1" max="1000" required class="form-control"
                                        disabled={!parameters.loginProtectionEnabled}
                                        value={parameters.lpIpMaxAttempts}
                                        onchange={e => { parameters!.lpIpMaxAttempts = e.currentTarget.valueAsNumber }} />
                                </FormGroup>
                            </div>
                            <div class="col-sm-6">
                                <FormGroup floating label="Failure window (minutes)">
                                    <input type="number" min="1" max="1440" required class="form-control"
                                        disabled={!parameters.loginProtectionEnabled}
                                        value={parameters.lpIpTimeWindowMinutes}
                                        onchange={e => { parameters!.lpIpTimeWindowMinutes = e.currentTarget.valueAsNumber }} />
                                </FormGroup>
                            </div>
                            <div class="col-6">
                                <FormGroup floating label="Initial block (min)">
                                    <input type="number" min="1" max="1440" required class="form-control"
                                        disabled={!parameters.loginProtectionEnabled}
                                        value={parameters.lpIpBaseBlockDurationMinutes}
                                        onchange={e => { parameters!.lpIpBaseBlockDurationMinutes = e.currentTarget.valueAsNumber }} />
                                </FormGroup>
                            </div>
                            <div class="col-6">
                                <FormGroup floating label="Backoff multiplier">
                                    <input type="number" min="1.0" max="10" step="0.5" required class="form-control"
                                        disabled={!parameters.loginProtectionEnabled}
                                        value={parameters.lpIpBlockDurationMultiplier}
                                        onchange={e => { parameters!.lpIpBlockDurationMultiplier = e.currentTarget.valueAsNumber }} />
                                </FormGroup>
                            </div>
                            <div class="col-6">
                                <FormGroup floating label="Max block (hours)">
                                    <input type="number" min="1" max="720" required class="form-control"
                                        disabled={!parameters.loginProtectionEnabled}
                                        value={parameters.lpIpMaxBlockDurationHours}
                                        onchange={e => { parameters!.lpIpMaxBlockDurationHours = e.currentTarget.valueAsNumber }} />
                                </FormGroup>
                            </div>
                            <div class="col-6">
                                <FormGroup floating label="Cooldown reset (hours)">
                                    <input type="number" min="1" max="720" required class="form-control"
                                        disabled={!parameters.loginProtectionEnabled}
                                        value={parameters.lpIpCooldownResetHours}
                                        onchange={e => { parameters!.lpIpCooldownResetHours = e.currentTarget.valueAsNumber }} />
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
                                    <input type="number" min="1" max="1000" required class="form-control"
                                        disabled={!parameters.loginProtectionEnabled}
                                        value={parameters.lpUserMaxAttempts}
                                        onchange={e => { parameters!.lpUserMaxAttempts = e.currentTarget.valueAsNumber }} />
                                </FormGroup>
                            </div>
                            <div class="col-sm-6">
                                <FormGroup floating label="Failure window (minutes)">
                                    <input type="number" min="1" max="1440" required class="form-control"
                                        disabled={!parameters.loginProtectionEnabled}
                                        value={parameters.lpUserTimeWindowMinutes}
                                        onchange={e => { parameters!.lpUserTimeWindowMinutes = e.currentTarget.valueAsNumber }} />
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
                                bind:checked={parameters.lpUserAutoUnlock} />
                            <div>Auto-unlock after timeout</div>
                        </label>
                        {#if parameters.lpUserAutoUnlock}
                            <FormGroup floating label="Auto-unlock delay (minutes)" class="mb-2">
                                <input type="number" min="1" max="10080" required class="form-control"
                                    disabled={!parameters.loginProtectionEnabled}
                                    value={parameters.lpUserLockoutDurationMinutes}
                                    onchange={e => { parameters!.lpUserLockoutDurationMinutes = e.currentTarget.valueAsNumber }} />
                            </FormGroup>
                        {/if}
                        <label
                            for="lpUserExemptAdmins"
                            class="d-flex align-items-center mb-2"
                        >
                            <Input
                                id="lpUserExemptAdmins"
                                class="mb-0 me-2"
                                type="switch"
                                disabled={!parameters.loginProtectionEnabled}
                                bind:checked={parameters.lpUserExemptAdmins} />
                            <div>Exempt admins from lockout</div>
                        </label>
                        <InfoBox class="mb-3">
                            Recommended: keeps an attacker from locking out an admin account by spamming its username. IP blocking still applies to everyone.
                        </InfoBox>

                        <p class="lp-group-title">Data retention</p>
                        <FormGroup floating label="Keep records for (days)" class="mb-3">
                            <input type="number" min="1" max="3650" required class="form-control"
                                disabled={!parameters.loginProtectionEnabled}
                                value={parameters.loginProtectionRetentionDays}
                                onchange={e => { parameters!.loginProtectionRetentionDays = e.currentTarget.valueAsNumber }} />
                        </FormGroup>

                        <small class="text-muted mt-2">
                            Manage active blocks &amp; lockouts on the <a href="/config/login-protection" use:link>Login protection</a> page.
                        </small>
                    {/if}
                </Section>
            </SectionedForm>

            <StickyActionBar>
                <AsyncButton type="button" class="btn btn-primary" disabled={!formValid} click={save}>
                    Save
                </AsyncButton>
            </StickyActionBar>
            </form>
        {/if}
        </Loadable>
    </PermissionGate>
</div>

<style>
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
</style>
