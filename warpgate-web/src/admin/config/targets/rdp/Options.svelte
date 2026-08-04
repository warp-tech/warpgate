<script lang="ts">
    import { FormGroup, Input } from '@sveltestrap/sveltestrap'
    import {
        RdpTlsSecurity,
        type TargetOptionsTargetRdpOptions,
    } from 'admin/lib/api'
    import HelpText from 'admin/lib/HelpText.svelte'

    interface Props {
        options: TargetOptionsTargetRdpOptions
        disabled?: boolean
    }

    let { options = $bindable(), disabled = false }: Props = $props()

    $effect(() => {
        options.tlsSecurity ??= RdpTlsSecurity.Tls12
    })
</script>

<h4 class="mt-4">Connection</h4>

<div class="row">
    <div class="col-8">
        <FormGroup floating label="Target host">
            <input class="form-control" bind:value={options.host} {disabled}>
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
                {disabled}
            >
        </FormGroup>
    </div>
</div>

<h4 class="mt-4">Authentication</h4>

<FormGroup floating label="Username">
    <input class="form-control" bind:value={options.username} {disabled}>
</FormGroup>

<FormGroup floating label="Domain (optional)">
    <input class="form-control" bind:value={options.domain} {disabled}>
</FormGroup>

{#if options.auth.kind === 'Password'}
    <FormGroup floating label="Password">
        <input
            class="form-control"
            type="password"
            bind:value={options.auth.password}
            {disabled}
        >
    </FormGroup>
{/if}

<h4 class="mt-4">TLS</h4>

<FormGroup floating label="Security level">
    <Input type="select" bind:value={options.tlsSecurity} {disabled}>
        <option value="Tls12">Windows 2016 / 10+ (TLS 1.2)</option>
        <option value="Tls12WithLegacyCiphers">
            Windows 2012 / 8+ (TLS 1.2 with legacy ciphers)
        </option>
        <option value="Tls10Unsafe">
            Windows 2008 R2 or older (TLS 1.0 with unsafe ciphers)
        </option>
    </Input>
</FormGroup>

<Input
    type="switch"
    label="Verify certificate"
    bind:checked={options.verifyTls}
    {disabled}
/>
<HelpText>
    Typically, RDP servers use self-signed certificates, so this is off by
    default.
</HelpText>
