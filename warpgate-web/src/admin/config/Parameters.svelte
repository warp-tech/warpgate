<script lang="ts">
    import { FormGroup, Input } from '@sveltestrap/sveltestrap'
    import { api, type ParameterValues } from 'admin/lib/api'
    import Loadable from 'common/Loadable.svelte'
    import RateLimitInput from 'common/RateLimitInput.svelte'
    import InfoBox from 'common/InfoBox.svelte'

    let parameters: ParameterValues | undefined = $state()
    const initPromise = init()

    async function init () {
        parameters = await api.getParameters({})
    }

    async function update() {
        await api.updateParameters({
            parameterUpdate: parameters!,
        })
    }
</script>

<div class="container-max-md">
    <div class="page-summary-bar">
    <h1>global parameters</h1>
    </div>

    <Loadable promise={initPromise}>
    {#if parameters}
        <h4 class="mt-4">Credentials</h4>
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

        <h4 class="mt-4">Traffic</h4>
        <FormGroup>
            <label class="mb-2" for="rateLimitBytesPerSecond">Global bandwidth limit</label>
            <RateLimitInput
                id="rateLimitBytesPerSecond"
                bind:value={parameters.rateLimitBytesPerSecond}
                change={update} />
        </FormGroup>

        <h4 class="mt-4">SSH</h4>
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
    {/if}
    </Loadable>
</div>
