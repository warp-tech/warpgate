<script lang="ts">
    import { Alert, Button, FormGroup, Input } from '@sveltestrap/sveltestrap'
    import AnalyticsConsentModal from 'admin/AnalyticsConsentModal.svelte'
    import {
        AnalyticsConsent,
        api,
        type ParameterValues,
        type PasswordLoginMode,
        type TargetClickAction,
    } from 'admin/lib/api'
    import HelpText from 'admin/lib/HelpText.svelte'
    import PermissionGate from 'admin/lib/PermissionGate.svelte'
    import Section from 'admin/lib/Section.svelte'
    import SectionedForm from 'admin/lib/SectionedForm.svelte'
    import Subsection from 'admin/lib/Subsection.svelte'
    import AsyncButton from 'common/AsyncButton.svelte'
    import { humantimeDuration } from 'common/duration'
    import { stringifyError } from 'common/errors'
    import InfoBox from 'common/InfoBox.svelte'
    import Loadable from 'common/Loadable.svelte'
    import RateLimitInput from 'common/RateLimitInput.svelte'
    import StickyActionBar from 'common/StickyActionBar.svelte'
    import { api as gatewayApi } from 'gateway/lib/api'
    import { reloadServerInfo } from 'gateway/lib/store'
    import { link } from 'svelte-spa-router'

    let parameters: ParameterValues | undefined = $state()
    let hasSsoProviders = $state(false)
    let updateError: string | undefined = $state()
    let formEl: HTMLFormElement | undefined = $state()
    let formValid = $state(true)

    // Cross-field hint: initial block longer than the cap will be clamped.
    const lpCapWarning = $derived.by(() => {
        if (!parameters?.loginProtectionEnabled) {
            return undefined
        }
        return parameters.lpIpBaseBlockDurationSeconds >
            parameters.lpIpMaxBlockDurationSeconds
            ? 'Initial block duration exceeds the maximum cap; it will be clamped to the maximum.'
            : undefined
    })

    const initPromise = init()

    async function init() {
        parameters = await api.getParameters({})
        const ssoProviders = await gatewayApi.getSsoProviders()
        hasSsoProviders = ssoProviders.length > 0
        return parameters
    }

    function refreshValidity() {
        formValid = formEl?.checkValidity() ?? false
    }

    $effect(() => {
        // Validate once the form has rendered with loaded values.
        if (formEl && parameters) {
            refreshValidity()
        }
    })

    async function save() {
        if (!parameters) return
        updateError = undefined
        try {
            // Cleared nullable fields must be sent as explicit null: undefined
            // is dropped by JSON.stringify, so the server keeps the old value.
            const parameterUpdate = {
                ...parameters,
                ticketMaxDurationSeconds:
                    parameters.ticketMaxDurationSeconds ?? null,
                ticketMaxUses: parameters.ticketMaxUses ?? null,
                maxApiTokenDurationSeconds:
                    parameters.maxApiTokenDurationSeconds ?? null,
                webAuthMaxAgeSeconds: parameters.webAuthMaxAgeSeconds ?? null,
                webApprovalGracePeriodSeconds:
                    parameters.webApprovalGracePeriodSeconds ?? null,
            } as unknown as ParameterValues
            await api.updateParameters({ parameterUpdate })
            await reloadServerInfo()
        } catch (err) {
            updateError = await stringifyError(err)
        }
    }

    let analyticsModalOpen = $state(false)

    const analyticsLabel = $derived.by(() => {
        if (
            !parameters ||
            parameters.analyticsConsent !== AnalyticsConsent.On
        ) {
            return 'Off'
        }
        return parameters.analyticsNormal ? 'Normal' : 'Reduced'
    })

    // Refresh only the analytics fields after the modal saves, leaving any
    // other unsaved edits on this page intact.
    async function refreshAnalytics() {
        if (!parameters) {
            return
        }
        const latest = await api.getParameters({})
        parameters.analyticsConsent = latest.analyticsConsent
        parameters.analyticsNormal = latest.analyticsNormal
    }
</script>

<div class="container-max-md">
    <div class="page-summary-bar">
        <h1>global parameters</h1>
    </div>

    <PermissionGate
        perm="configEdit"
        message="You have no permission to edit global parameters."
    >
        {#if updateError}
            <Alert
                color="danger"
                dismissible
                onclose={() => { updateError = undefined }}
                >{updateError}</Alert
            >
        {/if}
        <Loadable promise={initPromise}>
            {#snippet children(parameters)}
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
                                        bind:checked={parameters.allowOwnCredentialManagement}
                                    />
                                    <div>
                                        Allow users to manage their own
                                        credentials
                                    </div>
                                </label>
                            </Section>

                            <Section
                                id="password-policy"
                                title="Password policy"
                            >
                                <FormGroup
                                    floating
                                    label="Minimum length (0 = no requirement)"
                                >
                                    <input
                                        type="number"
                                        min="0"
                                        class="form-control"
                                        value={parameters.passwordPolicy.minLength}
                                        onchange={e => {
                                            const v = parseInt(e.currentTarget.value, 10)
                                            parameters.passwordPolicy.minLength = Number.isNaN(v) ? 0 : Math.max(0, v)
                                        }}
                                    >
                                </FormGroup>
                                <label
                                    for="requireUppercase"
                                    class="d-flex align-items-center mb-2"
                                >
                                    <Input
                                        id="requireUppercase"
                                        class="mb-0 me-2"
                                        type="switch"
                                        bind:checked={parameters.passwordPolicy.requireUppercase}
                                    />
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
                                        bind:checked={parameters.passwordPolicy.requireLowercase}
                                    />
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
                                        bind:checked={parameters.passwordPolicy.requireDigits}
                                    />
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
                                        bind:checked={parameters.passwordPolicy.requireSpecial}
                                    />
                                    <div>Require special character</div>
                                </label>
                            </Section>

                            <Section id="traffic" title="Traffic">
                                <Subsection title="Global bandwidth limit">
                                    <RateLimitInput
                                        id="rateLimitBytesPerSecond"
                                        bind:value={parameters.rateLimitBytesPerSecond}
                                        change={refreshValidity}
                                    />
                                </Subsection>
                            </Section>

                            <Section id="ssh" title="SSH">
                                <Subsection
                                    title="Allowed authentication methods"
                                >
                                    <label
                                        for="sshClientAuthPublickey"
                                        class="d-flex align-items-center mb-2"
                                    >
                                        <Input
                                            id="sshClientAuthPublickey"
                                            class="mb-0 me-2"
                                            type="switch"
                                            bind:checked={parameters.sshClientAuthPublickey}
                                        />
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
                                            bind:checked={parameters.sshClientAuthKeyboardInteractive}
                                        />
                                        <div>
                                            Keyboard-interactive authentication
                                            (OTP, 2FA prompts)
                                        </div>
                                    </label>
                                    <HelpText>
                                        Controls which authentication methods
                                        are offered to SSH clients. Disabling
                                        password authentication can help prevent
                                        brute-force attacks.
                                    </HelpText>
                                </Subsection>

                                <Subsection title="Quirks">
                                    <label
                                        for="recordScp"
                                        class="d-flex align-items-center mt-2"
                                    >
                                        <Input
                                            id="recordScp"
                                            class="mb-0 me-2"
                                            type="switch"
                                            bind:checked={parameters.recordScp}
                                        />
                                        <div>Record legacy SCP transfers</div>
                                    </label>
                                    <HelpText>
                                        Legacy SCP works over an exec channel
                                        and would be normally recorded like any
                                        other command. Disable to prevent SCP
                                        recordings from wasting storage space.
                                    </HelpText>

                                    <FormGroup>
                                        <label class="mb-2" for="sshBanner"
                                            >Login banner</label
                                        >
                                        <Input
                                            id="sshBanner"
                                            type="textarea"
                                            rows={4}
                                            bind:value={parameters.sshBanner}
                                        />
                                    </FormGroup>
                                    <HelpText class="mt-3 mb-3">
                                        Optional message shown to SSH clients
                                        during authentication.
                                    </HelpText>
                                </Subsection>
                            </Section>

                            <Section
                                id="tickets"
                                bodyTitle="Self-service tickets"
                                title="Tickets"
                            >
                                <label
                                    for="ticketSelfServiceEnabled"
                                    class="d-flex align-items-center mb-2"
                                >
                                    <Input
                                        id="ticketSelfServiceEnabled"
                                        class="mb-0 me-2"
                                        type="switch"
                                        bind:checked={parameters.ticketSelfServiceEnabled}
                                    />
                                    <div>Allow users to request tickets</div>
                                </label>
                                <InfoBox class="mt-3 mb-3">
                                    When enabled, authenticated users can
                                    request user-tied, time-limited access
                                    tickets from their profile page or via the
                                    API to a single target.
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
                                            bind:checked={parameters.ticketAutoApproveExistingAccess}
                                        />
                                        <div>
                                            Auto-approve when user already has
                                            role-based access
                                        </div>
                                    </label>

                                    <label
                                        for="ticketRequireDescription"
                                        class="d-flex align-items-center mb-2"
                                    >
                                        <Input
                                            id="ticketRequireDescription"
                                            class="mb-0 me-2"
                                            type="switch"
                                            bind:checked={parameters.ticketRequireDescription}
                                        />
                                        <div>
                                            Require description on ticket
                                            requests
                                        </div>
                                    </label>

                                    <label
                                        for="ticketRequestShowAllTargets"
                                        class="d-flex align-items-center mb-2"
                                    >
                                        <Input
                                            id="ticketRequestShowAllTargets"
                                            class="mb-0 me-2"
                                            type="switch"
                                            bind:checked={parameters.ticketRequestShowAllTargets}
                                        />
                                        <div>
                                            Show all targets in ticket request
                                            form
                                        </div>
                                    </label>
                                    <HelpText>
                                        When disabled, users only see targets
                                        they already have role-based access to.
                                    </HelpText>

                                    <Subsection title="Limits">
                                        <FormGroup
                                            floating
                                            label="Default max ticket duration (blank = unlimited)"
                                        >
                                            <input
                                                type="text"
                                                class="form-control"
                                                placeholder="e.g. 8h, 30m, 1d"
                                                use:humantimeDuration={{ seconds: parameters.ticketMaxDurationSeconds, onChange: v => { parameters.ticketMaxDurationSeconds = v } }}
                                            >
                                        </FormGroup>
                                        <HelpText>
                                            Global default. Can be overridden
                                            per target. Examples: 30m, 8h, 1d,
                                            2h30m.
                                        </HelpText>

                                        <FormGroup
                                            floating
                                            label="Max uses per ticket (blank = unlimited)"
                                        >
                                            <input
                                                type="number"
                                                min="1"
                                                class="form-control"
                                                value={parameters.ticketMaxUses ?? ''}
                                                onchange={e => {
                                                    const v = parseInt(e.currentTarget.value, 10)
                                                    parameters.ticketMaxUses = Number.isNaN(v) ? undefined : v
                                                }}
                                            >
                                        </FormGroup>
                                    </Subsection>
                                {/if}
                            </Section>

                            <Section id="api-tokens" title="API tokens">
                                <FormGroup
                                    floating
                                    label="Maximum API token duration (blank = unlimited)"
                                >
                                    <input
                                        type="text"
                                        class="form-control"
                                        placeholder="e.g. 8h, 30m, 1d"
                                        use:humantimeDuration={{ seconds: parameters.maxApiTokenDurationSeconds, onChange: v => { parameters.maxApiTokenDurationSeconds = v } }}
                                    >
                                </FormGroup>
                            </Section>

                            <Section id="ui" title="UI">
                                <label
                                    for="webClientsEnabled"
                                    class="d-flex align-items-center"
                                >
                                    <Input
                                        id="webClientsEnabled"
                                        class="mb-0 me-2"
                                        type="switch"
                                        bind:checked={parameters.webClientsEnabled}
                                    />
                                    <div>
                                        Enable in-browser clients (SSH terminal,
                                        RDP/VNC desktop)
                                    </div>
                                </label>
                                <HelpText>
                                    Lets users open SSH, RDP and VNC targets
                                    directly in the browser from the portal.
                                    When off, only native-client connection
                                    instructions are shown.
                                </HelpText>

                                <FormGroup
                                    floating
                                    label="SSH target click action"
                                >
                                    <select
                                        id="targetClickAction"
                                        class="form-select"
                                        value={parameters.targetClickAction ?? 'Connect'}
                                        onchange={e => parameters.targetClickAction = e.currentTarget.value as TargetClickAction}
                                    >
                                        <option value="Connect">
                                            Open web terminal
                                        </option>
                                        <option value="ShowInstructions">
                                            Show connection instructions
                                        </option>
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
                                        bind:checked={parameters.showSessionMenu}
                                    />
                                    <div>Show HTTP session menu</div>
                                </label>
                                <HelpText>
                                    Warpgate can inject a session menu into HTTP
                                    sessions, allowing users to log out or
                                    return back to the home page.
                                </HelpText>
                            </Section>

                            <Section id="login" title="Login">
                                {#if hasSsoProviders}
                                    <FormGroup floating label="Password login">
                                        <select
                                            id="passwordLoginMode"
                                            class="form-select"
                                            value={parameters.passwordLoginMode ?? 'Enabled'}
                                            onchange={e => parameters.passwordLoginMode = e.currentTarget.value as PasswordLoginMode}
                                        >
                                            <option value="Enabled">
                                                Enabled
                                            </option>
                                            <option value="Minimized">
                                                Minimized (hidden behind a link)
                                            </option>
                                            <option value="Disabled">
                                                Disabled (SSO only)
                                            </option>
                                        </select>
                                    </FormGroup>
                                    <HelpText>
                                        Minimized hides the username and
                                        password fields behind a link, with the
                                        focus on the SSO buttons. Disabled
                                        removes password login entirely and the
                                        server rejects password attempts — make
                                        sure all users can sign in via SSO
                                        first.
                                    </HelpText>

                                    <FormGroup
                                        floating
                                        label="Require re-authentication after (blank = never)"
                                    >
                                        <input
                                            type="text"
                                            class="form-control"
                                            placeholder="e.g. 8h, 30m, 1d"
                                            use:humantimeDuration={{ seconds: parameters.webAuthMaxAgeSeconds, onChange: v => { parameters.webAuthMaxAgeSeconds = v } }}
                                        >
                                    </FormGroup>
                                    <HelpText>
                                        Forces users to sign in again once
                                        before accessing Web SSH or creating
                                        tickets if at least this much time has
                                        passed since they've logged in. Native
                                        SSH/database sessions are unaffected.
                                    </HelpText>
                                {/if}

                                <FormGroup
                                    floating
                                    label="Web approval cache period"
                                >
                                    <input
                                        type="text"
                                        class="form-control"
                                        placeholder="e.g. 5m, 1h"
                                        use:humantimeDuration={{ seconds: parameters.webApprovalGracePeriodSeconds, onChange: v => { parameters.webApprovalGracePeriodSeconds = v } }}
                                    >
                                </FormGroup>
                                <HelpText>
                                    After a user approves an in-browser
                                    authentication request, remember the
                                    approval for this period and do not request
                                    it for new sessions by the same user to the
                                    same target from the same IP. Blank = never
                                    cache approvals.
                                </HelpText>
                            </Section>

                            <Section
                                id="login-protection"
                                title="Login protection"
                            >
                                <!-- Master toggle -->
                                <label
                                    for="loginProtectionEnabled"
                                    class="d-flex align-items-center"
                                >
                                    <Input
                                        id="loginProtectionEnabled"
                                        class="mb-0 me-2"
                                        type="switch"
                                        bind:checked={parameters.loginProtectionEnabled}
                                    />
                                    <div>Enable brute-force protection</div>
                                </label>
                                <HelpText>
                                    Rate-limits IPs and locks accounts after
                                    repeated failed logins. When disabled, all
                                    settings below are preserved but not
                                    enforced.
                                </HelpText>

                                {#if lpCapWarning}
                                    <Alert color="warning" class="mb-2"
                                        >{lpCapWarning}</Alert
                                    >
                                {/if}

                                {#if parameters.loginProtectionEnabled}
                                    <Subsection title="IP rate-limit">
                                        <div class="row g-2 mb-2">
                                            <div class="col-sm-6">
                                                <FormGroup
                                                    floating
                                                    label="Max failures before IP block"
                                                >
                                                    <input
                                                        type="number"
                                                        min="1"
                                                        max="1000"
                                                        required
                                                        class="form-control"
                                                        disabled={!parameters.loginProtectionEnabled}
                                                        value={parameters.lpIpMaxAttempts}
                                                        onchange={e => { parameters.lpIpMaxAttempts = e.currentTarget.valueAsNumber }}
                                                    >
                                                </FormGroup>
                                            </div>
                                            <div class="col-sm-6">
                                                <FormGroup
                                                    floating
                                                    label="Failure window"
                                                >
                                                    <input
                                                        type="text"
                                                        class="form-control"
                                                        placeholder="e.g. 15m"
                                                        use:humantimeDuration={{ seconds: parameters.lpIpTimeWindowSeconds, onChange: v => { if (v != null) { parameters.lpIpTimeWindowSeconds = v } } }}
                                                    >
                                                </FormGroup>
                                            </div>
                                            <div class="col-6">
                                                <FormGroup
                                                    floating
                                                    label="Initial block"
                                                >
                                                    <input
                                                        type="text"
                                                        class="form-control"
                                                        placeholder="e.g. 30m"
                                                        use:humantimeDuration={{ seconds: parameters.lpIpBaseBlockDurationSeconds, onChange: v => { if (v != null) { parameters.lpIpBaseBlockDurationSeconds = v } } }}
                                                    >
                                                </FormGroup>
                                            </div>
                                            <div class="col-6">
                                                <FormGroup
                                                    floating
                                                    label="Backoff multiplier"
                                                >
                                                    <input
                                                        type="number"
                                                        min="1.0"
                                                        max="10"
                                                        step="0.5"
                                                        required
                                                        class="form-control"
                                                        disabled={!parameters.loginProtectionEnabled}
                                                        value={parameters.lpIpBlockDurationMultiplier}
                                                        onchange={e => { parameters.lpIpBlockDurationMultiplier = e.currentTarget.valueAsNumber }}
                                                    >
                                                </FormGroup>
                                            </div>
                                            <div class="col-6">
                                                <FormGroup
                                                    floating
                                                    label="Max block"
                                                >
                                                    <input
                                                        type="text"
                                                        class="form-control"
                                                        placeholder="e.g. 24h"
                                                        use:humantimeDuration={{ seconds: parameters.lpIpMaxBlockDurationSeconds, onChange: v => { if (v != null) { parameters.lpIpMaxBlockDurationSeconds = v } } }}
                                                    >
                                                </FormGroup>
                                            </div>
                                            <div class="col-6">
                                                <FormGroup
                                                    floating
                                                    label="Cooldown reset"
                                                >
                                                    <input
                                                        type="text"
                                                        class="form-control"
                                                        placeholder="e.g. 24h"
                                                        use:humantimeDuration={{ seconds: parameters.lpIpCooldownResetSeconds, onChange: v => { if (v != null) { parameters.lpIpCooldownResetSeconds = v } } }}
                                                    >
                                                </FormGroup>
                                            </div>
                                        </div>
                                        <HelpText>
                                            Each block is
                                            <strong
                                                >multiplier × the previous block
                                                duration</strong
                                            >, capped at the maximum. The repeat
                                            count resets only after the cooldown
                                            period of <em>clean</em> activity —
                                            not when a block expires.
                                        </HelpText>

                                        <Subsection title="User lockout">
                                            <div class="row g-2 mb-2">
                                                <div class="col-sm-6">
                                                    <FormGroup
                                                        floating
                                                        label="Max failures before lockout"
                                                    >
                                                        <input
                                                            type="number"
                                                            min="1"
                                                            max="1000"
                                                            required
                                                            class="form-control"
                                                            disabled={!parameters.loginProtectionEnabled}
                                                            value={parameters.lpUserMaxAttempts}
                                                            onchange={e => { parameters.lpUserMaxAttempts = e.currentTarget.valueAsNumber }}
                                                        >
                                                    </FormGroup>
                                                </div>
                                                <div class="col-sm-6">
                                                    <FormGroup
                                                        floating
                                                        label="Failure window"
                                                    >
                                                        <input
                                                            type="text"
                                                            class="form-control"
                                                            placeholder="e.g. 60m"
                                                            use:humantimeDuration={{ seconds: parameters.lpUserTimeWindowSeconds, onChange: v => { if (v != null) { parameters.lpUserTimeWindowSeconds = v } } }}
                                                        >
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
                                                    bind:checked={parameters.lpUserAutoUnlock}
                                                />
                                                <div>
                                                    Auto-unlock after timeout
                                                </div>
                                            </label>
                                            {#if parameters.lpUserAutoUnlock}
                                                <FormGroup
                                                    floating
                                                    label="Auto-unlock delay"
                                                    class="mb-2"
                                                >
                                                    <input
                                                        type="text"
                                                        class="form-control"
                                                        placeholder="e.g. 60m"
                                                        use:humantimeDuration={{ seconds: parameters.lpUserLockoutDurationSeconds, onChange: v => { if (v != null) { parameters.lpUserLockoutDurationSeconds = v } } }}
                                                    >
                                                </FormGroup>
                                            {/if}
                                        </Subsection>

                                        <Subsection title="Lockout protection">
                                            <label
                                                for="lpUserExemptAdmins"
                                                class="d-flex align-items-center mb-2"
                                            >
                                                <Input
                                                    id="lpUserExemptAdmins"
                                                    class="mb-0 me-2"
                                                    type="switch"
                                                    disabled={!parameters.loginProtectionEnabled}
                                                    bind:checked={parameters.lpUserExemptAdmins}
                                                />
                                                <div>
                                                    Exempt admins from lockout
                                                </div>
                                            </label>
                                            <HelpText class="mb-3">
                                                Recommended: keeps an attacker
                                                from locking out an admin
                                                account by spamming its
                                                username. IP blocking still
                                                applies to everyone.
                                            </HelpText>
                                        </Subsection>

                                        <Subsection title="Data retention">
                                            <FormGroup
                                                floating
                                                label="Keep records for"
                                                class="mb-3"
                                            >
                                                <input
                                                    type="text"
                                                    class="form-control"
                                                    placeholder="e.g. 30d"
                                                    use:humantimeDuration={{ seconds: parameters.loginProtectionRetentionSeconds, onChange: v => { if (v != null) { parameters.loginProtectionRetentionSeconds = v } } }}
                                                >
                                            </FormGroup>
                                        </Subsection>

                                        <InfoBox>
                                            Manage active blocks &amp; lockouts
                                            on the
                                            <a
                                                href="/config/login-protection"
                                                use:link
                                                >Login protection</a
                                            >
                                            page.
                                        </InfoBox>
                                    </Subsection>
                                {/if}
                            </Section>

                            <Section
                                id="installation-counter"
                                title="Installation counter"
                            >
                                <div class="d-flex align-items-center">
                                    <div>
                                        Reporting:
                                        <strong>{analyticsLabel}</strong>
                                    </div>
                                    <Button
                                        class="ms-auto"
                                        color="secondary"
                                        onclick={() => analyticsModalOpen = true}
                                        >Change</Button
                                    >
                                </div>
                            </Section>
                        </SectionedForm>

                        <StickyActionBar>
                            <AsyncButton
                                type="button"
                                class="btn btn-primary"
                                disabled={!formValid}
                                click={save}
                            >
                                Save
                            </AsyncButton>
                        </StickyActionBar>
                    </form>
                {/if}
            {/snippet}
        </Loadable>
    </PermissionGate>

    {#if parameters}
        <AnalyticsConsentModal
            bind:isOpen={analyticsModalOpen}
            initialConsent={parameters.analyticsConsent}
            initialNormal={parameters.analyticsNormal}
            onsaved={refreshAnalytics}
        />
    {/if}
</div>
