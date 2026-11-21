<script lang="ts">
    import { FormGroup, Input } from '@sveltestrap/sveltestrap'
    import type {
        MfaEnforcement,
        ParameterValues,
        PasswordLoginMode,
    } from 'admin/lib/api'
    import HelpText from 'admin/lib/HelpText.svelte'
    import Section from 'admin/lib/Section.svelte'
    import Subsection from 'admin/lib/Subsection.svelte'
    import DurationInput from 'common/DurationInput.svelte'
    import InfoBox from 'common/InfoBox.svelte'
    import { api as gatewayApi } from 'gateway/lib/api'
    import { link } from 'svelte-spa-router'
    import ParametersForm from './ParametersForm.svelte'

    let parameters: ParameterValues | undefined = $state()

    let hasSsoProviders = $state(false)
    gatewayApi.getSsoProviders().then(providers => {
        hasSsoProviders = providers.length > 0
    })
</script>

<ParametersForm title="authentication" bind:parameters>
    {#snippet children(parameters)}
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
                        const v = parseInt(e.currentTarget.value, 10)
                        parameters.passwordPolicy.minLength = Number.isNaN(v)
                            ? 0
                            : Math.max(0, v)
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
            <label for="requireDigits" class="d-flex align-items-center mb-2">
                <Input
                    id="requireDigits"
                    class="mb-0 me-2"
                    type="switch"
                    bind:checked={parameters.passwordPolicy.requireDigits}
                />
                <div>Require digit</div>
            </label>
            <label for="requireSpecial" class="d-flex align-items-center">
                <Input
                    id="requireSpecial"
                    class="mb-0 me-2"
                    type="switch"
                    bind:checked={parameters.passwordPolicy.requireSpecial}
                />
                <div>Require special character</div>
            </label>
        </Section>

        <Section id="login" title="Login">
            {#if hasSsoProviders}
                <FormGroup floating label="Password login">
                    <select
                        id="passwordLoginMode"
                        class="form-select"
                        value={parameters.passwordLoginMode ?? 'Enabled'}
                        onchange={e =>
                            (parameters.passwordLoginMode = e.currentTarget
                                .value as PasswordLoginMode)}
                    >
                        <option value="Enabled">Enabled</option>
                        <option value="Minimized">
                            Minimized (hidden behind a link)
                        </option>
                        <option value="Disabled">Disabled (SSO only)</option>
                    </select>
                </FormGroup>
                <HelpText>
                    Minimized hides the username and password fields behind a
                    link, with the focus on the SSO buttons. Disabled removes
                    password login entirely and the server rejects password
                    attempts — make sure all users can sign in via SSO first.
                </HelpText>

                <DurationInput
                    label="Require re-authentication after (blank = never)"
                    seconds={parameters.webAuthMaxAgeSeconds}
                    onChange={v => {
                        parameters.webAuthMaxAgeSeconds = v
                    }}
                />
                <HelpText>
                    Forces users to sign in again once before accessing Web SSH
                    or creating tickets if at least this much time has passed
                    since they've logged in. Native SSH/database sessions are
                    unaffected.
                </HelpText>
            {/if}

            <FormGroup>
                <label class="mb-2" for="mfaEnforcement">
                    MFA enforcement
                </label>
                <select
                    id="mfaEnforcement"
                    class="form-select"
                    value={parameters.mfaEnforcement ?? 'Off'}
                    onchange={e =>
                        (parameters.mfaEnforcement = e.currentTarget
                            .value as MfaEnforcement)}
                >
                    <option value="Off">Off</option>
                    <option value="Enroll">
                        Enroll (users must set up an OTP when they log in on the
                        web)
                    </option>
                    <option value="Require">
                        Require (prevent any logins without a second factor)
                    </option>
                </select>
            </FormGroup>

            <Input
                class="mb-0 me-2"
                type="switch"
                label="Exempt SSO users from MFA enforcement"
                bind:checked={parameters.mfaPolicyExemptSsoUsers}
            />
            <HelpText>
                Enable if you already enforce MFA at your SSO provider
            </HelpText>

            <FormGroup>
                <label class="mb-2" for="banner"> Login banner </label>
                <Input
                    id="banner"
                    type="textarea"
                    rows={4}
                    bind:value={parameters.banner}
                />
            </FormGroup>
            <HelpText class="mt-3 mb-3">
                Optional message shown to users when they connect to a target:
                during SSH authentication, as a modal in the UI and proxied HTTP
                targets, on the RDP/VNC hold screen and as a PostgreSQL
                connection notice.
            </HelpText>
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
                    bind:checked={parameters.ticketSelfServiceEnabled}
                />
                <div>Allow users to request tickets</div>
            </label>
            <InfoBox class="mt-3 mb-3">
                When enabled, authenticated users can request user-tied,
                time-limited access tickets from their profile page or via the
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
                        Auto-approve when user already has role-based access
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
                        bind:checked={parameters.ticketRequestShowAllTargets}
                    />
                    <div>Show all targets in ticket request form</div>
                </label>
                <HelpText>
                    When disabled, users only see targets they already have
                    role-based access to.
                </HelpText>

                <Subsection title="Limits">
                    <DurationInput
                        label="Default max ticket duration (blank = unlimited)"
                        seconds={parameters.ticketMaxDurationSeconds}
                        onChange={v => {
                            parameters.ticketMaxDurationSeconds = v
                        }}
                    />
                    <HelpText>
                        Global default. Can be overridden per target. Examples:
                        30m, 8h, 1d, 2h30m.
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
                                parameters.ticketMaxUses = Number.isNaN(v)
                                    ? undefined
                                    : v
                            }}
                        >
                    </FormGroup>
                </Subsection>
            {/if}
        </Section>

        <Section id="api-tokens" title="API tokens">
            <DurationInput
                label="Maximum API token duration (blank = unlimited)"
                seconds={parameters.maxApiTokenDurationSeconds}
                onChange={v => {
                    parameters.maxApiTokenDurationSeconds = v
                }}
            />
        </Section>
    {/snippet}
</ParametersForm>
