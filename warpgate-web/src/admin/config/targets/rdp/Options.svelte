<script lang="ts">
    import { FormGroup, Input } from '@sveltestrap/sveltestrap'
    import {
        RdpTargetCompression,
        RdpTlsSecurity,
        type TargetOptionsTargetRdpOptions,
    } from 'admin/lib/api'
    import HelpText from 'admin/lib/HelpText.svelte'
    import Section from 'admin/lib/Section.svelte'
    import SecretRefInput from 'common/SecretRefInput.svelte'

    interface Props {
        id: string
        name: string
        options: TargetOptionsTargetRdpOptions
    }

    let { id, name, options = $bindable() }: Props = $props()
</script>

<Section title="Connection" id="connection">
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
</Section>

<Section title="Authentication" id="authentication">
    <FormGroup floating label="Username">
        <input class="form-control" bind:value={options.username}>
    </FormGroup>

    <FormGroup floating label="Domain (optional)">
        <input class="form-control" bind:value={options.domain}>
    </FormGroup>

    <FormGroup floating label="Kerberos KDC URL (optional)">
        <input
            class="form-control"
            bind:value={options.kdcUrl}
            placeholder="tcp://dc.example.com:88"
            pattern="(tcp|udp|https?)://.+"
            maxlength="2048"
        >
    </FormGroup>
    <HelpText>
        Enables Kerberos authentication (required for Protected Users).
        <code>tcp://</code>, <code>udp://</code> or a KDC proxy
        <code>https://</code>
        URL. Kerberos authentication requires that you use a DNS name for the
        target address.
    </HelpText>

    {#if options.auth.kind === 'Password'}
        <SecretRefInput
            bind:value={options.auth.password}
            inlineLabel="Password"
            intendedUsage={{
                kind: 'Target',
                id,
                name,
            }}
        />
    {/if}

    <Input
        type="switch"
        label="Interactive logon"
        bind:checked={options.interactiveLogon}
    />
    <HelpText>
        Shows the target's sign-in screen instead of logging on automatically.
        The credentials above are still used for network-level authentication.
    </HelpText>
</Section>

<Section title="TLS" id="tls">
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
</Section>

<Section title="Quality" id="quality">
    <FormGroup floating label="Compression between Warpgate and target">
        <Input type="select" bind:value={options.compression}>
            <option value={RdpTargetCompression.Lossless}>Lossless</option>
            <option value={RdpTargetCompression.Remotefx}>RemoteFX</option>
            <option value={RdpTargetCompression.GraphicsPipeline}>
                Graphics pipeline (experimental)
            </option>
        </Input>
    </FormGroup>
    <HelpText>
        If Warpgate and the RDP server are in the same network, lossless
        compression will significantly improve image quality, even if the client
        is connecting remotely. GNOME Remote Desktop and KDE KRDP require the
        graphics pipeline.
    </HelpText>
</Section>
