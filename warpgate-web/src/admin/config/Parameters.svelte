<script lang="ts">
    import AnalyticsConsentModal from 'admin/AnalyticsConsentModal.svelte'
    import {
        AnalyticsConsent,
        api,
        type MfaEnforcement,
        type OpenTargetsInNewTabMode,
        type ParameterValues,
        type PasswordLoginMode,
        type SshHostKeyVerificationMode,
        type TargetClickAction,
    } from 'admin/lib/api'
    import HelpText from 'admin/lib/HelpText.svelte'
    import PermissionGate from 'admin/lib/PermissionGate.svelte'
    import Section from 'admin/lib/Section.svelte'
    import SectionedForm from 'admin/lib/SectionedForm.svelte'
    import Subsection from 'admin/lib/Subsection.svelte'
    import { humantimeDuration } from 'common/duration'
    import { stringifyError } from 'common/errors'
    import InfoBox from 'common/InfoBox.svelte'
    import Loadable from 'common/Loadable.svelte'
    import RateLimitInput from 'common/RateLimitInput.svelte'
    import StickyActionBar from 'common/StickyActionBar.svelte'
    import { api as gatewayApi } from 'gateway/lib/api'
    import { reloadServerInfo } from 'gateway/lib/store'
    import { link } from 'svelte-spa-router'
    import Button from 'ui/Button.svelte'
    import Callout from 'ui/Callout.svelte'
    import Checkbox from 'ui/Checkbox.svelte'
    import Input from 'ui/Input.svelte'
    import Textarea from 'ui/Textarea.svelte'

    let parameters: ParameterValues | undefined = $state()
    let hasSsoProviders = $state(false)

    // Switching the storage kind / credential mode replaces the object with a
    // fresh variant, since the tagged enum can't hold both shapes at once.
    function setStorageKind(kind: string): void {
        if (!parameters) {
            return
        }
        parameters.recordingsStorage =
            kind === 'S3'
                ? {
                      kind: 'S3',
                      bucket: '',
                      region: 'us-east-1',
                      pathStyle: false,
                      prefix: '',
                      credentials: { mode: 'Auto' },
                  }
                : { kind: 'Disk', path: './data/recordings' }
    }

    function setCredentialMode(mode: string): void {
        if (parameters?.recordingsStorage.kind !== 'S3') {
            return
        }
        // Omit secretAccessKey so an untouched field keeps the stored secret.
        parameters.recordingsStorage.credentials =
            mode === 'Static'
                ? { mode: 'Static', accessKeyId: '' }
                : { mode: 'Auto' }
    }
    let updateError: string | undefined = $state()
    let testResult: { success: boolean; error?: string } | undefined = $state()

    // Sends the edited config as-is; an untouched secret round-trips as
    // undefined and the server refills it from the stored value.
    async function testStorage(): Promise<void> {
        if (parameters?.recordingsStorage.kind !== 'S3') {
            return
        }
        testResult = undefined
        testResult = await api.testRecordingsStorage({
            recordingsStorageConfig: parameters.recordingsStorage,
        })
        if (!testResult.success) {
            throw new Error(testResult.error ?? 'Connection failed')
        }
    }

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
                rateLimitBytesPerSecond:
                    parameters.rateLimitBytesPerSecond ?? null,
                ticketMaxDurationSeconds:
                    parameters.ticketMaxDurationSeconds ?? null,
                ticketMaxUses: parameters.ticketMaxUses ?? null,
                maxApiTokenDurationSeconds:
                    parameters.maxApiTokenDurationSeconds ?? null,
                webAuthMaxAgeSeconds: parameters.webAuthMaxAgeSeconds ?? null,
                webApprovalGracePeriodSeconds:
                    parameters.webApprovalGracePeriodSeconds ?? null,
                adminApprovalTimeoutSeconds:
                    parameters.adminApprovalTimeoutSeconds ?? null,
                adminApprovalGracePeriodSeconds:
                    parameters.adminApprovalGracePeriodSeconds ?? null,
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
            <div class="notice">
                <Callout tone="danger" title="Could not save">
                    {updateError}
                    {#snippet actions()}
                        <Button
                            size="compact"
                            variant="ghost"
                            onclick={() => (updateError = undefined)}
                        >
                            Dismiss
                        </Button>
                    {/snippet}
                </Callout>
            </div>
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
                                <Checkbox
                                    label="Allow users to manage their own credentials"
                                    bind:checked={parameters.allowOwnCredentialManagement}
                                />
                            </Section>

                            <Section
                                id="password-policy"
                                title="Password policy"
                            >
                                <label class="wg-field-group">
                                    <span class="wg-field-label"
                                        >Minimum length (0 = no
                                        requirement)</span
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
                                </label>
                                <Checkbox
                                    label="Require uppercase letter"
                                    bind:checked={parameters.passwordPolicy.requireUppercase}
                                />
                                <Checkbox
                                    label="Require lowercase letter"
                                    bind:checked={parameters.passwordPolicy.requireLowercase}
                                />
                                <Checkbox
                                    label="Require digit"
                                    bind:checked={parameters.passwordPolicy.requireDigits}
                                />
                                <Checkbox
                                    label="Require special character"
                                    bind:checked={parameters.passwordPolicy.requireSpecial}
                                />
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
                                    <Checkbox
                                        label="Public key authentication"
                                        bind:checked={parameters.sshClientAuthPublickey}
                                    />
                                    <Checkbox
                                        label="Password authentication"
                                        bind:checked={parameters.sshClientAuthPassword}
                                    />
                                    <Checkbox
                                        label="Keyboard-interactive authentication (OTP, 2FA prompts)"
                                        bind:checked={parameters.sshClientAuthKeyboardInteractive}
                                    />
                                    <HelpText>
                                        Controls which authentication methods
                                        are offered to SSH clients. Disabling
                                        password authentication can help prevent
                                        brute-force attacks.
                                    </HelpText>
                                </Subsection>

                                <Subsection title="Target host keys">
                                    <label class="wg-field-group">
                                        <span class="wg-field-label"
                                            >Unknown host key handling</span
                                        >

                                        <select
                                            id="sshHostKeyVerification"
                                            class="form-select"
                                            value={parameters.sshHostKeyVerification ?? 'Prompt'}
                                            onchange={e => parameters.sshHostKeyVerification = e.currentTarget.value as SshHostKeyVerificationMode}
                                        >
                                            <option value="Prompt">
                                                Ask the user to trust the key
                                            </option>
                                            <option value="AutoAccept">
                                                Trust and remember the key
                                            </option>
                                            <option value="AutoReject">
                                                Refuse to connect
                                            </option>
                                            <option value="Ignore">
                                                Don't check host keys at all
                                            </option>
                                        </select>
                                    </label>
                                </Subsection>

                                <Subsection title="Quirks">
                                    {#if parameters.recordingsEnable}
                                        <Checkbox
                                            label="Record legacy SCP transfers"
                                            bind:checked={parameters.recordScp}
                                        />
                                        <HelpText>
                                            Legacy SCP works over an exec
                                            channel and would be normally
                                            recorded like any other command.
                                            Disable to prevent SCP recordings
                                            from wasting storage space.
                                        </HelpText>
                                    {/if}
                                </Subsection>
                            </Section>

                            <Section
                                id="tickets"
                                bodyTitle="Self-service tickets"
                                title="Tickets"
                            >
                                <Checkbox
                                    label="Allow users to request tickets"
                                    bind:checked={parameters.ticketSelfServiceEnabled}
                                />
                                <InfoBox class="mt-3 mb-3">
                                    When enabled, authenticated users can
                                    request user-tied, time-limited access
                                    tickets from their profile page or via the
                                    API to a single target.
                                </InfoBox>

                                {#if parameters.ticketSelfServiceEnabled}
                                    <Checkbox
                                        label="Auto-approve when user already has role-based access"
                                        bind:checked={parameters.ticketAutoApproveExistingAccess}
                                    />

                                    <Checkbox
                                        label="Require description on ticket requests"
                                        bind:checked={parameters.ticketRequireDescription}
                                    />

                                    <Checkbox
                                        label="Show all targets in ticket request form"
                                        bind:checked={parameters.ticketRequestShowAllTargets}
                                    />
                                    <HelpText>
                                        When disabled, users only see targets
                                        they already have role-based access to.
                                    </HelpText>

                                    <Subsection title="Limits">
                                        <label class="wg-field-group">
                                            <span class="wg-field-label"
                                                >Default max ticket duration
                                                (blank = unlimited)</span
                                            >

                                            <input
                                                type="text"
                                                class="form-control"
                                                placeholder="e.g. 8h, 30m, 1d"
                                                use:humantimeDuration={{ seconds: parameters.ticketMaxDurationSeconds, onChange: v => { parameters.ticketMaxDurationSeconds = v } }}
                                            >
                                        </label>
                                        <HelpText>
                                            Global default. Can be overridden
                                            per target. Examples: 30m, 8h, 1d,
                                            2h30m.
                                        </HelpText>

                                        <label class="wg-field-group">
                                            <span class="wg-field-label"
                                                >Max uses per ticket (blank =
                                                unlimited)</span
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
                                        </label>
                                    </Subsection>
                                {/if}
                            </Section>

                            <Section id="api-tokens" title="API tokens">
                                <label class="wg-field-group">
                                    <span class="wg-field-label"
                                        >Maximum API token duration (blank =
                                        unlimited)</span
                                    >

                                    <input
                                        type="text"
                                        class="form-control"
                                        placeholder="e.g. 8h, 30m, 1d"
                                        use:humantimeDuration={{ seconds: parameters.maxApiTokenDurationSeconds, onChange: v => { parameters.maxApiTokenDurationSeconds = v } }}
                                    >
                                </label>
                            </Section>

                            <Section id="ui" title="UI">
                                <Checkbox
                                    label="Enable in-browser clients (SSH terminal, RDP/VNC desktop)"
                                    bind:checked={parameters.webClientsEnabled}
                                />
                                <HelpText>
                                    Lets users open SSH, RDP and VNC targets
                                    directly in the browser from the portal.
                                    When off, only native-client connection
                                    instructions are shown.
                                </HelpText>

                                <label class="wg-field-group">
                                    <span class="wg-field-label"
                                        >SSH target click action</span
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
                                </label>

                                <label class="wg-field-group">
                                    <span class="wg-field-label"
                                        >Open targets in</span
                                    >

                                    <select
                                        id="openTargetsInNewTab"
                                        class="form-select"
                                        value={parameters.openTargetsInNewTab ?? 'DefaultOn'}
                                        onchange={e => parameters.openTargetsInNewTab = e.currentTarget.value as OpenTargetsInNewTabMode}
                                    >
                                        <option value="DefaultOn">
                                            New tab by default
                                        </option>
                                        <option value="DefaultOff">
                                            Same tab by default
                                        </option>
                                        <option value="ForcedOn">
                                            Always a new tab
                                        </option>
                                        <option value="ForcedOff">
                                            Always the same tab
                                        </option>
                                    </select>
                                </label>

                                <Checkbox
                                    label="Show HTTP session menu"
                                    bind:checked={parameters.showSessionMenu}
                                />
                                <HelpText>
                                    Warpgate can inject a session menu into HTTP
                                    sessions, allowing users to log out or
                                    return back to the home page.
                                </HelpText>
                            </Section>

                            <Section id="login" title="Login">
                                {#if hasSsoProviders}
                                    <label class="wg-field-group">
                                        <span class="wg-field-label"
                                            >Password login</span
                                        >

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
                                    </label>
                                    <HelpText>
                                        Minimized hides the username and
                                        password fields behind a link, with the
                                        focus on the SSO buttons. Disabled
                                        removes password login entirely and the
                                        server rejects password attempts — make
                                        sure all users can sign in via SSO
                                        first.
                                    </HelpText>

                                    <label class="wg-field-group">
                                        <span class="wg-field-label"
                                            >Require re-authentication after
                                            (blank = never)</span
                                        >

                                        <input
                                            type="text"
                                            class="form-control"
                                            placeholder="e.g. 8h, 30m, 1d"
                                            use:humantimeDuration={{ seconds: parameters.webAuthMaxAgeSeconds, onChange: v => { parameters.webAuthMaxAgeSeconds = v } }}
                                        >
                                    </label>
                                    <HelpText>
                                        Forces users to sign in again once
                                        before accessing Web SSH or creating
                                        tickets if at least this much time has
                                        passed since they've logged in. Native
                                        SSH/database sessions are unaffected.
                                    </HelpText>
                                {/if}

                                <label class="wg-field-group">
                                    <span class="wg-field-label"
                                        >Web approval cache period</span
                                    >

                                    <input
                                        type="text"
                                        class="form-control"
                                        placeholder="e.g. 5m, 1h"
                                        use:humantimeDuration={{ seconds: parameters.webApprovalGracePeriodSeconds, onChange: v => { parameters.webApprovalGracePeriodSeconds = v } }}
                                    >
                                </label>
                                <HelpText>
                                    After a user approves an in-browser
                                    authentication request, remember the
                                    approval for this period and do not request
                                    it for new sessions by the same user to the
                                    same target from the same IP. Blank = never
                                    cache approvals.
                                </HelpText>

                                <div class="wg-field-group">
                                    <label class="mb-2" for="mfaEnforcement">
                                        MFA enforcement
                                    </label>
                                    <select
                                        id="mfaEnforcement"
                                        class="form-select"
                                        value={parameters.mfaEnforcement ?? 'Off'}
                                        onchange={e => parameters.mfaEnforcement = e.currentTarget.value as MfaEnforcement}
                                    >
                                        <option value="Off">Off</option>
                                        <option value="Enroll">
                                            Enroll (users must set up an OTP
                                            when they log in on the web)
                                        </option>
                                        <option value="Require">
                                            Require (prevent any logins without
                                            a second factor)
                                        </option>
                                    </select>
                                </div>

                                <Checkbox
                                    label="Exempt SSO users from MFA enforcement"
                                    bind:checked={parameters.mfaPolicyExemptSsoUsers}
                                />
                                <HelpText>
                                    Enable if you already enforce MFA at your
                                    SSO provider
                                </HelpText>

                                <div class="wg-field-group">
                                    <Textarea
                                        id="banner"
                                        label="Login banner"
                                        rows={4}
                                        mono={false}
                                        spellcheck
                                        bind:value={parameters.banner}
                                    />
                                </div>
                                <HelpText class="mt-3 mb-3">
                                    Optional message shown to users when they
                                    connect to a target: during SSH
                                    authentication, as a modal in the UI and
                                    proxied HTTP targets, on the RDP/VNC hold
                                    screen and as a PostgreSQL connection
                                    notice.
                                </HelpText>
                            </Section>

                            <Section
                                id="session-approvals"
                                title="Session approvals"
                            >
                                <label class="wg-field-group">
                                    <span class="wg-field-label"
                                        >Approval timeout</span
                                    >

                                    <input
                                        type="text"
                                        class="form-control"
                                        placeholder="e.g. 5m, 1h"
                                        use:humantimeDuration={{ seconds: parameters.adminApprovalTimeoutSeconds, onChange: v => { parameters.adminApprovalTimeoutSeconds = v } }}
                                    >
                                </label>
                                <HelpText>
                                    A session held for administrator approval is
                                    rejected if not approved within this time.
                                    Blank = use the default 10 minute timeout.
                                </HelpText>

                                <label class="wg-field-group">
                                    <span class="wg-field-label"
                                        >Admin approval cache period</span
                                    >

                                    <input
                                        type="text"
                                        class="form-control"
                                        placeholder="e.g. 5m, 1h"
                                        use:humantimeDuration={{ seconds: parameters.adminApprovalGracePeriodSeconds, onChange: v => { parameters.adminApprovalGracePeriodSeconds = v } }}
                                    >
                                </label>
                                <HelpText>
                                    After an administrator approves a session,
                                    remember the approval for this period and do
                                    not request it for new sessions by the same
                                    user to the same target from the same IP.
                                    Blank = never cache approvals.
                                </HelpText>
                            </Section>

                            <Section
                                id="login-protection"
                                title="Login protection"
                            >
                                <!-- Master toggle -->
                                <Checkbox
                                    label="Enable brute-force protection"
                                    bind:checked={parameters.loginProtectionEnabled}
                                />
                                <HelpText>
                                    Rate-limits IPs and locks accounts after
                                    repeated failed logins. When disabled, all
                                    settings below are preserved but not
                                    enforced.
                                </HelpText>

                                {#if lpCapWarning}
                                    <Callout tone="warning">
                                        {lpCapWarning}
                                    </Callout>
                                {/if}

                                {#if parameters.loginProtectionEnabled}
                                    <Subsection title="IP rate-limit">
                                        <div class="row g-2 mb-2">
                                            <div class="col-sm-6">
                                                <label class="wg-field-group">
                                                    <span class="wg-field-label"
                                                        >Max failures before IP
                                                        block</span
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
                                                </label>
                                            </div>
                                            <div class="col-sm-6">
                                                <label class="wg-field-group">
                                                    <span class="wg-field-label"
                                                        >Failure window</span
                                                    >

                                                    <input
                                                        type="text"
                                                        class="form-control"
                                                        placeholder="e.g. 15m"
                                                        use:humantimeDuration={{ seconds: parameters.lpIpTimeWindowSeconds, onChange: v => { if (v != null) { parameters.lpIpTimeWindowSeconds = v } } }}
                                                    >
                                                </label>
                                            </div>
                                            <div class="col-6">
                                                <label class="wg-field-group">
                                                    <span class="wg-field-label"
                                                        >Initial block</span
                                                    >

                                                    <input
                                                        type="text"
                                                        class="form-control"
                                                        placeholder="e.g. 30m"
                                                        use:humantimeDuration={{ seconds: parameters.lpIpBaseBlockDurationSeconds, onChange: v => { if (v != null) { parameters.lpIpBaseBlockDurationSeconds = v } } }}
                                                    >
                                                </label>
                                            </div>
                                            <div class="col-6">
                                                <label class="wg-field-group">
                                                    <span class="wg-field-label"
                                                        >Backoff
                                                        multiplier</span
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
                                                </label>
                                            </div>
                                            <div class="col-6">
                                                <label class="wg-field-group">
                                                    <span class="wg-field-label"
                                                        >Max block</span
                                                    >

                                                    <input
                                                        type="text"
                                                        class="form-control"
                                                        placeholder="e.g. 24h"
                                                        use:humantimeDuration={{ seconds: parameters.lpIpMaxBlockDurationSeconds, onChange: v => { if (v != null) { parameters.lpIpMaxBlockDurationSeconds = v } } }}
                                                    >
                                                </label>
                                            </div>
                                            <div class="col-6">
                                                <label class="wg-field-group">
                                                    <span class="wg-field-label"
                                                        >Cooldown reset</span
                                                    >

                                                    <input
                                                        type="text"
                                                        class="form-control"
                                                        placeholder="e.g. 24h"
                                                        use:humantimeDuration={{ seconds: parameters.lpIpCooldownResetSeconds, onChange: v => { if (v != null) { parameters.lpIpCooldownResetSeconds = v } } }}
                                                    >
                                                </label>
                                            </div>
                                        </div>
                                        <HelpText>
                                            Each block is
                                            <strong>
                                                multiplier × the previous block
                                                duration
                                            </strong>
                                            , capped at the maximum. The repeat
                                            count resets only after the cooldown
                                            period of
                                            <em>clean</em>
                                            activity — not when a block expires.
                                        </HelpText>

                                        <Subsection title="User lockout">
                                            <div class="row g-2 mb-2">
                                                <div class="col-sm-6">
                                                    <label
                                                        class="wg-field-group"
                                                    >
                                                        <span
                                                            class="wg-field-label"
                                                            >Max failures before
                                                            lockout</span
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
                                                    </label>
                                                </div>
                                                <div class="col-sm-6">
                                                    <label
                                                        class="wg-field-group"
                                                    >
                                                        <span
                                                            class="wg-field-label"
                                                            >Failure
                                                            window</span
                                                        >

                                                        <input
                                                            type="text"
                                                            class="form-control"
                                                            placeholder="e.g. 60m"
                                                            use:humantimeDuration={{ seconds: parameters.lpUserTimeWindowSeconds, onChange: v => { if (v != null) { parameters.lpUserTimeWindowSeconds = v } } }}
                                                        >
                                                    </label>
                                                </div>
                                            </div>
                                            <Checkbox
                                                label="Auto-unlock after timeout"
                                                bind:checked={parameters.lpUserAutoUnlock}
                                            />
                                            {#if parameters.lpUserAutoUnlock}
                                                <label class="wg-field-group">
                                                    <span class="wg-field-label"
                                                        >Auto-unlock delay</span
                                                    >

                                                    <input
                                                        type="text"
                                                        class="form-control"
                                                        placeholder="e.g. 60m"
                                                        use:humantimeDuration={{ seconds: parameters.lpUserLockoutDurationSeconds, onChange: v => { if (v != null) { parameters.lpUserLockoutDurationSeconds = v } } }}
                                                    >
                                                </label>
                                            {/if}
                                        </Subsection>

                                        <Subsection title="Lockout protection">
                                            <Checkbox
                                                label="Exempt admins from lockout"
                                                bind:checked={parameters.lpUserExemptAdmins}
                                            />
                                            <HelpText class="mb-3">
                                                Recommended: keeps an attacker
                                                from locking out an admin
                                                account by spamming its
                                                username. IP blocking still
                                                applies to everyone.
                                            </HelpText>
                                        </Subsection>

                                        <Subsection title="Data retention">
                                            <label class="wg-field-group">
                                                <span class="wg-field-label"
                                                    >Keep records for</span
                                                >

                                                <input
                                                    type="text"
                                                    class="form-control"
                                                    placeholder="e.g. 30d"
                                                    use:humantimeDuration={{ seconds: parameters.loginProtectionRetentionSeconds, onChange: v => { if (v != null) { parameters.loginProtectionRetentionSeconds = v } } }}
                                                >
                                            </label>
                                        </Subsection>

                                        <InfoBox>
                                            Manage active blocks &amp; lockouts
                                            on the
                                            <a
                                                href="/status/login-protection"
                                                use:link
                                            >
                                                Login protection
                                            </a>
                                            page.
                                        </InfoBox>
                                    </Subsection>
                                {/if}
                            </Section>

                            <Section id="recordings" title="Session recordings">
                                <Checkbox
                                    label="Record sessions"
                                    bind:checked={parameters.recordingsEnable}
                                />

                                {#if parameters.recordingsEnable}
                                    <Checkbox
                                        label="Record remote desktop keyboard input"
                                        bind:checked={parameters.recordDesktopKeyboardInput}
                                    />
                                    <HelpText>
                                        Disable if recording passwords typed in
                                        by users in various applications is a
                                        security concern.
                                    </HelpText>
                                {/if}

                                <label class="wg-field-group">
                                    <span class="wg-field-label"
                                        >Storage backend</span
                                    >

                                    <select
                                        id="recordingsStorage"
                                        class="form-select"
                                        value={parameters.recordingsStorage.kind}
                                        onchange={e => setStorageKind(e.currentTarget.value)}
                                    >
                                        <option value="Disk">Local disk</option>
                                        <option value="S3">
                                            S3 / S3-compatible
                                        </option>
                                    </select>
                                </label>

                                <HelpText>
                                    Changing the storage location applies to new
                                    recordings only, copy existing recordings to
                                    the new location manually.
                                </HelpText>

                                {#if parameters.recordingsStorage.kind === 'Disk'}
                                    {@const disk = parameters.recordingsStorage}
                                    <label class="wg-field-group">
                                        <span class="wg-field-label"
                                            >Recordings path</span
                                        >

                                        <input
                                            type="text"
                                            class="form-control"
                                            bind:value={disk.path}
                                        >
                                    </label>
                                {:else if parameters.recordingsStorage.kind === 'S3'}
                                    {@const s3 = parameters.recordingsStorage}
                                    <label class="wg-field-group">
                                        <span class="wg-field-label"
                                            >Bucket</span
                                        >

                                        <input
                                            type="text"
                                            class="form-control"
                                            required
                                            bind:value={s3.bucket}
                                        >
                                    </label>
                                    <HelpText>
                                        The bucket needs a CORS policy allowing
                                        this origin to issue GET requests with a
                                        Range header.
                                    </HelpText>
                                    <label class="wg-field-group">
                                        <span class="wg-field-label"
                                            >Region</span
                                        >

                                        <input
                                            type="text"
                                            class="form-control"
                                            placeholder="us-east-1"
                                            required
                                            bind:value={s3.region}
                                        >
                                    </label>
                                    <label class="wg-field-group">
                                        <span class="wg-field-label"
                                            >Endpoint (blank = AWS)</span
                                        >

                                        <input
                                            type="text"
                                            class="form-control"
                                            placeholder="https://minio.example.com:9000"
                                            value={s3.endpoint ?? ''}
                                            oninput={e => s3.endpoint = e.currentTarget.value || undefined}
                                        >
                                    </label>
                                    <label class="wg-field-group">
                                        <span class="wg-field-label"
                                            >Key prefix</span
                                        >

                                        <input
                                            type="text"
                                            class="form-control"
                                            bind:value={s3.prefix}
                                        >
                                    </label>
                                    <Checkbox
                                        label="Path-style addressing"
                                        bind:checked={s3.pathStyle}
                                    />
                                    <HelpText>
                                        Most S3-compatible services (e.g. MinIO,
                                        RustFS) require path-style addressing.
                                    </HelpText>

                                    <label class="wg-field-group">
                                        <span class="wg-field-label"
                                            >Credentials</span
                                        >

                                        <select
                                            id="recordingsS3CredentialMode"
                                            class="form-select"
                                            value={s3.credentials.mode}
                                            onchange={e => setCredentialMode(e.currentTarget.value)}
                                        >
                                            <option value="Auto">
                                                Automatic (environment or
                                                role-based)
                                            </option>
                                            <option value="Static">
                                                Access key
                                            </option>
                                        </select>
                                    </label>

                                    {#if s3.credentials.mode === 'Static'}
                                        {@const creds = s3.credentials}
                                        <label class="wg-field-group">
                                            <span class="wg-field-label"
                                                >Access key ID</span
                                            >

                                            <input
                                                type="text"
                                                class="form-control"
                                                autocomplete="off"
                                                bind:value={creds.accessKeyId}
                                            >
                                        </label>
                                        <label class="wg-field-group">
                                            <span class="wg-field-label"
                                                >Secret access key</span
                                            >

                                            <input
                                                type="password"
                                                class="form-control"
                                                autocomplete="off"
                                                placeholder="********"
                                                bind:value={creds.secretAccessKey}
                                            >
                                        </label>
                                    {/if}

                                    <Button
                                        type="button"
                                        variant="secondary"
                                        click={testStorage}
                                    >
                                        Test connection
                                    </Button>
                                    {#if testResult}
                                        <Callout
                                            tone={testResult.success
                                                ? 'success'
                                                : 'danger'}
                                        >
                                            {testResult.success
                                                ? 'Connection successful'
                                                : testResult.error}
                                        </Callout>
                                    {/if}
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
                                        variant="secondary"
                                        onclick={() => analyticsModalOpen = true}
                                    >
                                        Change
                                    </Button>
                                </div>
                            </Section>
                        </SectionedForm>

                        <StickyActionBar>
                            <Button
                                type="button"
                                class="btn btn-primary"
                                disabled={!formValid}
                                click={save}
                            >
                                Save
                            </Button>
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

<style>
    /* The save-error callout. This screen had no <style> block at all, which
       is why the class resolved to nothing. */
    .notice {
        margin-bottom: var(--wg-space-lg);
    }
</style>
