<script lang="ts">
    import { FormGroup } from '@sveltestrap/sveltestrap'
    import { type TargetOptionsTargetRdpOptions } from '../../../lib/api'

    interface Props {
        options: TargetOptionsTargetRdpOptions,
    }

    let { options = $bindable() }: Props = $props()
</script>

<h4 class="mt-4">Connection</h4>

<div class="row">
    <div class="col-8">
        <FormGroup floating label="Target host">
            <input class="form-control" bind:value={options.host} />
        </FormGroup>
    </div>
    <div class="col-4">
        <FormGroup floating label="Target port">
            <input class="form-control" type="number" bind:value={options.port} min="1" max="65535" step="1" />
        </FormGroup>
    </div>
</div>

<h4 class="mt-4">Authentication</h4>

<FormGroup floating label="Username">
    <input class="form-control" bind:value={options.username} />
</FormGroup>

<FormGroup floating label="Domain (optional)">
    <input class="form-control" bind:value={options.domain} />
</FormGroup>

{#if options.auth.kind === 'Password'}
    <FormGroup floating label="Password">
        <input class="form-control" type="password" bind:value={options.auth.password} />
    </FormGroup>
{/if}

<h4 class="mt-4">TLS</h4>

<div class="form-check">
    <input class="form-check-input" type="checkbox" id="rdp-verify-tls" bind:checked={options.verifyTls} />
    <label class="form-check-label" for="rdp-verify-tls">
        Verify server certificate
    </label>
</div>
<div class="text-muted small mt-1">
    Many RDP servers use self-signed certificates; leave off unless the server presents a certificate trusted by the OS.
</div>
