<script lang="ts">
    import { FormGroup, Input } from '@sveltestrap/sveltestrap'
    import {
        api,
        type OpenTargetsInNewTabMode,
        type ParameterValues,
        type TargetClickAction,
    } from 'admin/lib/api'
    import HelpText from 'admin/lib/HelpText.svelte'
    import LogoInput from 'admin/lib/LogoInput.svelte'
    import Section from 'admin/lib/Section.svelte'
    import Subsection from 'admin/lib/Subsection.svelte'
    import ParametersForm from './ParametersForm.svelte'

    let parameters: ParameterValues | undefined = $state()

    let pendingLogo: string | null | undefined = $state()

    // An untouched logo round-trips as undefined, which the server ignores.
    async function afterSave() {
        if (pendingLogo !== undefined && parameters) {
            parameters.logoEtag = (await api.getParameters({})).logoEtag
            pendingLogo = undefined
        }
    }
</script>

<ParametersForm
    title="UI"
    bind:parameters
    extraUpdate={() => ({ logo: pendingLogo })}
    onsaved={afterSave}
>
    {#snippet children(parameters)}
        <Section id="logo" title="Custom logo">
            <LogoInput etag={parameters.logoEtag} bind:value={pendingLogo} />
        </Section>

        <Section id="web-client" title="Web clients">
            <label for="webClientsEnabled" class="d-flex align-items-center">
                <Input
                    id="webClientsEnabled"
                    class="mb-0 me-2"
                    type="switch"
                    bind:checked={parameters.webClientsEnabled}
                />
                <div>
                    Enable in-browser clients (SSH terminal, RDP/VNC desktop)
                </div>
            </label>
            <HelpText>
                Lets users open SSH, RDP and VNC targets directly in the browser
                from the portal. When off, only native-client connection
                instructions are shown.
            </HelpText>

            {#if parameters.webClientsEnabled}
                <FormGroup floating label="SSH target click action">
                    <select
                        id="targetClickAction"
                        class="form-select"
                        value={parameters.targetClickAction ?? 'Connect'}
                        onchange={e =>
                            (parameters.targetClickAction = e.currentTarget
                                .value as TargetClickAction)}
                    >
                        <option value="Connect">Open web terminal</option>
                        <option value="ShowInstructions">
                            Show connection instructions
                        </option>
                    </select>
                </FormGroup>
            {/if}
        </Section>

        <Section id="behavior" title="Behavior">
            <FormGroup floating label="Open targets in">
                <select
                    id="openTargetsInNewTab"
                    class="form-select"
                    value={parameters.openTargetsInNewTab ?? 'DefaultOn'}
                    onchange={e =>
                        (parameters.openTargetsInNewTab = e.currentTarget
                            .value as OpenTargetsInNewTabMode)}
                >
                    <option value="DefaultOn">New tab by default</option>
                    <option value="DefaultOff">Same tab by default</option>
                    <option value="ForcedOn">Always a new tab</option>
                    <option value="ForcedOff">Always the same tab</option>
                </select>
            </FormGroup>

            <label for="showSessionMenu" class="d-flex align-items-center">
                <Input
                    id="showSessionMenu"
                    class="mb-0 me-2"
                    type="switch"
                    bind:checked={parameters.showSessionMenu}
                />
                <div>Show HTTP session menu</div>
            </label>
            <HelpText>
                Warpgate can inject a session menu into HTTP sessions, allowing
                users to log out or return back to the home page.
            </HelpText>
        </Section>
    {/snippet}
</ParametersForm>
