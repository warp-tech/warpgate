<script lang="ts">
    import { FormGroup, Input } from '@sveltestrap/sveltestrap'
    import {
        RdpTargetCompression,
        RdpTlsSecurity,
        type TargetOptionsTargetRdpOptions,
    } from 'admin/lib/api'
    import HelpText from 'admin/lib/HelpText.svelte'

    interface Props {
        options: TargetOptionsTargetRdpOptions
    }

    let { options = $bindable() }: Props = $props()

    $effect(() => {
        options.tlsSecurity ??= RdpTlsSecurity.Tls12
    })
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

<Input
    type="switch"
    label="Interactive logon"
    bind:checked={options.interactiveLogon}
/>
<HelpText>
    Shows the target's sign-in screen instead of logging on automatically. The
    credentials above are still used for network-level authentication.
</HelpText>

<h4 class="mt-4">TLS</h4>

<FormGroup floating label="Security level">
    <Input type="select" bind:value={options.tlsSecurity}>
        <option value={RdpTlsSecurity.Tls12}>
            Windows 2016 / 10+ (TLS 1.2)
        </option>
        <option value={RdpTlsSecurity.Tls12WithLegacyCiphers}>
            Windows 2012 / 8+ (TLS 1.2 with legacy ciphers)
        </option>
        <option value={RdpTlsSecurity.Tls10Unsafe}>
            Windows 2008 R2 or older (TLS 1.0 with unsafe ciphers)
        </option>
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

<h4 class="mt-4">Quality</h4>
<FormGroup floating label="Compression between Warpgate and target">
    <Input type="select" bind:value={options.compression}>
        <option value={RdpTargetCompression.Lossless}>Lossless</option>
        <option value={RdpTargetCompression.Remotefx}>RemoteFX</option>
    </Input>
</FormGroup>
<HelpText>
    If Warpgate and the RDP server are in the same network, lossless compression
    will significantly improve image quality, even if the client is connecting
    remotely.
</HelpText>
