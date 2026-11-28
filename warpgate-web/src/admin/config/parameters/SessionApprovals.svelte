<script lang="ts">
    import type { ParameterValues } from 'admin/lib/api'
    import HelpText from 'admin/lib/HelpText.svelte'
    import Section from 'admin/lib/Section.svelte'
    import DurationInput from 'common/DurationInput.svelte'
    import OnboardingHint from 'common/OnboardingHint.svelte'
    import ParametersForm from './ParametersForm.svelte'

    let parameters: ParameterValues | undefined = $state()
</script>

<ParametersForm title="session approvals" bind:parameters>
    {#snippet children(parameters)}
        <Section id="web-approvals" title="User self-approvals">
            <OnboardingHint>
                These are the approvals confirmed by the user themselves,
                triggered when the auth policy requires "in-browser approval",
                or the user has no other credentials.
            </OnboardingHint>

            <DurationInput
                label="Web approval cache period"
                seconds={parameters.webApprovalGracePeriodSeconds}
                onChange={v => {
                    parameters.webApprovalGracePeriodSeconds = v
                }}
            />
            <HelpText>
                After a user approves their own in-browser authentication
                request, remember the approval for this period and do not
                request it for new sessions by the same user to the same target
                from the same IP.
            </HelpText>
            <HelpText> Blank = never cache approvals. </HelpText>
        </Section>

        <Section id="admin-approvals" title="Admin approvals">
            <OnboardingHint>
                These are the just-in-time session approvals for targets where
                they are explicitly enabled
            </OnboardingHint>

            <DurationInput
                label="Approval timeout"
                seconds={parameters.adminApprovalTimeoutSeconds}
                onChange={v => {
                    parameters.adminApprovalTimeoutSeconds = v
                }}
            />
            <HelpText>
                A session held for administrator approval is rejected if not
                approved within this time.
            </HelpText>
            <HelpText> Blank = use the default 10 minute timeout. </HelpText>

            <DurationInput
                label="Admin approval cache period"
                seconds={parameters.adminApprovalGracePeriodSeconds}
                onChange={v => {
                    parameters.adminApprovalGracePeriodSeconds = v
                }}
            />
            <HelpText>
                After an administrator approves a session, remember the approval
                for this period and do not request it for new sessions by the
                same user to the same target from the same IP.
            </HelpText>
            <HelpText> Blank = never cache approvals. </HelpText>
        </Section>
    {/snippet}
</ParametersForm>
