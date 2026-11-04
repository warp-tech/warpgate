<script lang="ts">
    import { Alert, FormGroup, Input } from '@sveltestrap/sveltestrap'
    import type { ParameterValues } from 'admin/lib/api'
    import HelpText from 'admin/lib/HelpText.svelte'
    import Subsection from 'admin/lib/Subsection.svelte'
    import DurationInput from 'common/DurationInput.svelte'
    import InfoBox from 'common/InfoBox.svelte'
    import { link } from 'svelte-spa-router'
    import ParametersForm from './ParametersForm.svelte'

    let parameters: ParameterValues | undefined = $state()

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
</script>

<ParametersForm title="login protection" bind:parameters>
    {#snippet children(parameters)}
        <!-- Master toggle -->
        <label for="loginProtectionEnabled" class="d-flex align-items-center">
            <Input
                id="loginProtectionEnabled"
                class="mb-0 me-2"
                type="switch"
                bind:checked={parameters.loginProtectionEnabled}
            />
            <div>Enable brute-force protection</div>
        </label>
        <HelpText>
            Rate-limits IPs and locks accounts after repeated failed logins.
            When disabled, all settings below are preserved but not enforced.
        </HelpText>

        {#if lpCapWarning}
            <Alert color="warning" class="mb-2">{lpCapWarning}</Alert>
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
                                onchange={e => {
                                    parameters.lpIpMaxAttempts =
                                        e.currentTarget.valueAsNumber
                                }}
                            >
                        </FormGroup>
                    </div>
                    <div class="col-sm-6">
                        <DurationInput
                            label="Failure window"
                            seconds={parameters.lpIpTimeWindowSeconds}
                            onChange={v => {
                                if (v != null) {
                                    parameters.lpIpTimeWindowSeconds = v
                                }
                            }}
                        />
                    </div>
                    <div class="col-6">
                        <DurationInput
                            label="Initial block"
                            seconds={parameters.lpIpBaseBlockDurationSeconds}
                            onChange={v => {
                                if (v != null) {
                                    parameters.lpIpBaseBlockDurationSeconds = v
                                }
                            }}
                        />
                    </div>
                    <div class="col-6">
                        <FormGroup floating label="Backoff multiplier">
                            <input
                                type="number"
                                min="1.0"
                                max="10"
                                step="0.5"
                                required
                                class="form-control"
                                disabled={!parameters.loginProtectionEnabled}
                                value={parameters.lpIpBlockDurationMultiplier}
                                onchange={e => {
                                    parameters.lpIpBlockDurationMultiplier =
                                        e.currentTarget.valueAsNumber
                                }}
                            >
                        </FormGroup>
                    </div>
                    <div class="col-6">
                        <DurationInput
                            label="Max block"
                            seconds={parameters.lpIpMaxBlockDurationSeconds}
                            onChange={v => {
                                if (v != null) {
                                    parameters.lpIpMaxBlockDurationSeconds = v
                                }
                            }}
                        />
                    </div>
                    <div class="col-6">
                        <DurationInput
                            label="Cooldown reset"
                            seconds={parameters.lpIpCooldownResetSeconds}
                            onChange={v => {
                                if (v != null) {
                                    parameters.lpIpCooldownResetSeconds = v
                                }
                            }}
                        />
                    </div>
                </div>
                <HelpText>
                    Each block is
                    <strong> multiplier × the previous block duration </strong>
                    , capped at the maximum. The repeat count resets only after
                    the cooldown period of
                    <em>clean</em>
                    activity — not when a block expires.
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
                                    onchange={e => {
                                        parameters.lpUserMaxAttempts =
                                            e.currentTarget.valueAsNumber
                                    }}
                                >
                            </FormGroup>
                        </div>
                        <div class="col-sm-6">
                            <DurationInput
                                label="Failure window"
                                seconds={parameters.lpUserTimeWindowSeconds}
                                onChange={v => {
                                    if (v != null) {
                                        parameters.lpUserTimeWindowSeconds = v
                                    }
                                }}
                            />
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
                        <div>Auto-unlock after timeout</div>
                    </label>
                    {#if parameters.lpUserAutoUnlock}
                        <DurationInput
                            label="Auto-unlock delay"
                            seconds={parameters.lpUserLockoutDurationSeconds}
                            onChange={v => {
                                if (v != null) {
                                    parameters.lpUserLockoutDurationSeconds = v
                                }
                            }}
                            class="mb-2"
                        />
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
                        <div>Exempt admins from lockout</div>
                    </label>
                    <HelpText class="mb-3">
                        Recommended: keeps an attacker from locking out an admin
                        account by spamming its username. IP blocking still
                        applies to everyone.
                    </HelpText>
                </Subsection>

                <Subsection title="Data retention">
                    <DurationInput
                        label="Keep records for"
                        seconds={parameters.loginProtectionRetentionSeconds}
                        onChange={v => {
                            if (v != null) {
                                parameters.loginProtectionRetentionSeconds = v
                            }
                        }}
                        class="mb-3"
                    />
                </Subsection>

                <InfoBox>
                    Manage active blocks &amp; lockouts on the
                    <a href="/status/login-protection" use:link>
                        Login protection
                    </a>
                    page.
                </InfoBox>
            </Subsection>
        {/if}
    {/snippet}
</ParametersForm>
