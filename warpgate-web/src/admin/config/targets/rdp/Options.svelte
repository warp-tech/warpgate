<script lang="ts">
    import { FormGroup, Input } from '@sveltestrap/sveltestrap'
    import type { TargetOptionsTargetRdpOptions } from 'admin/lib/api'
    import HelpText from 'admin/lib/HelpText.svelte'

    interface Props {
        options: TargetOptionsTargetRdpOptions
    }

    let { options = $bindable() }: Props = $props()
</script>

<h4 class="mt-4">Connection</h4>

<div class="row">
    <div class="col-8">
        <FormGroup floating label="Target host">
            <input class="form-control" bind:value={options.host}>
        </FormGroup>
    </div>
    <div class="col-4">
        <FormGroup floating label="Target port">
            <input
                class="form-control"
                type="number"
                bind:value={options.port}
                min="1"
                max="65535"
                step="1"
            >
        </FormGroup>
    </div>
</div>

<h4 class="mt-4">Authentication</h4>

<FormGroup floating label="Username">
    <input class="form-control" bind:value={options.username}>
</FormGroup>

<FormGroup floating label="Domain (optional)">
    <input class="form-control" bind:value={options.domain}>
</FormGroup>

{#if options.auth.kind === 'Password'}
    <FormGroup floating label="Password">
        <input
            class="form-control"
            type="password"
            bind:value={options.auth.password}
        >
    </FormGroup>
{/if}

<h4 class="mt-4">TLS</h4>

<FormGroup floating label="TLS backend">
    <Input type="select" bind:value={options.tlsBackend}>
        <option value="Rustls">rustls</option>
        <option value="OpenSslLegacy">OpenSSL legacy</option>
    </Input>
</FormGroup>

<Input
    type="switch"
    label="Verify certificate"
    bind:checked={options.verifyTls}
/>
<HelpText>
    Typically, RDP servers use self-signed certificates, so this is off by
    default.
</HelpText>

{#if options.tlsBackend === 'OpenSslLegacy'}
    <FormGroup floating label="OpenSSL cipher list">
        <input
            class="form-control"
            bind:value={options.tlsOpensslCipherList}
            placeholder="Use Warpgate default"
        >
    </FormGroup>
    <HelpText>
        Leave empty to use the Windows Server 2012 compatibility list. TLS 1.2
        remains the minimum.
    </HelpText>
{/if}
