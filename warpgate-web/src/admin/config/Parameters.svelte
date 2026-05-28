<script lang="ts">
    import { FormGroup, Input } from '@sveltestrap/sveltestrap'
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
            </SectionedForm>
        {/if}
        </Loadable>
    </PermissionGate>
</div>
