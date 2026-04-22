<script lang="ts">
    import { FormGroup, Input } from '@sveltestrap/sveltestrap'
    import { api, type ParameterValues } from 'admin/lib/api'
    import { api as gatewayApi } from 'gateway/lib/api'
    import Loadable from 'common/Loadable.svelte'
    import RateLimitInput from 'common/RateLimitInput.svelte'
    import InfoBox from 'common/InfoBox.svelte'
    import PermissionGate from 'admin/lib/PermissionGate.svelte'

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
    }
</script>

<div class="container-max-md">
    <div class="page-summary-bar">
        <h1>global parameters</h1>
    </div>

    <PermissionGate perm="configEdit" message="You have no permission to edit global parameters.">
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

            <h4 class="mt-4">HTTP</h4>
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
                <div>Show session menu</div>
            </label>
            <InfoBox class="mt-3 mb-3">
                Warpgate can inject a session menu into HTTP sessions, allowing users to log out or return back to the home page.
            </InfoBox>

            {#if hasSsoProviders}
            <h4 class="mt-4">Login</h4>
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
            {/if}
        {/if}
        </Loadable>
    </PermissionGate>
</div>
