<script lang="ts">
    import { FormGroup, Input } from '@sveltestrap/sveltestrap'
    import type {
        ParameterValues,
        SshHostKeyVerificationMode,
    } from 'admin/lib/api'
    import HelpText from 'admin/lib/HelpText.svelte'
    import Section from 'admin/lib/Section.svelte'
    import Subsection from 'admin/lib/Subsection.svelte'
    import ParametersForm from './ParametersForm.svelte'

    let parameters: ParameterValues | undefined = $state()
</script>

<ParametersForm title="SSH" bind:parameters>
    {#snippet children(parameters)}
        <Section id="methods" title="Allowed authentication methods">
            <HelpText>
                Controls which authentication methods are offered to SSH
                clients. Disabling password authentication can help prevent
                brute-force attacks.
            </HelpText>
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
                    Keyboard-interactive authentication (OTP, 2FA prompts)
                </div>
            </label>

            <Subsection title="Target host keys">
                <FormGroup floating label="Unknown host key handling">
                    <select
                        id="sshHostKeyVerification"
                        class="form-select"
                        value={parameters.sshHostKeyVerification ?? 'Prompt'}
                        onchange={e =>
                            (parameters.sshHostKeyVerification = e.currentTarget
                                .value as SshHostKeyVerificationMode)}
                    >
                        <option value="Prompt">
                            Ask the user to trust the key
                        </option>
                        <option value="AutoAccept">
                            Trust and remember the key
                        </option>
                        <option value="AutoReject">Refuse to connect</option>
                        <option value="Ignore">
                            Don't check host keys at all
                        </option>
                    </select>
                </FormGroup>
            </Subsection>
        </Section>

        <Section id="terminal" title="Terminal display">
            <label
                for="sshShowQrCode"
                class="d-flex align-items-center"
            >
                <Input
                    id="sshShowQrCode"
                    class="mb-0 me-2"
                    type="switch"
                    bind:checked={parameters.sshShowQrCode}
                />
                <div>Display QR code for login URLs</div>
            </label>
            <HelpText>
                Shows a scannable QR code in the terminal when web
                authentication is required.
            </HelpText>
        </Section>
    {/snippet}
</ParametersForm>
