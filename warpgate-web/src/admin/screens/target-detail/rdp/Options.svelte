<script lang="ts">
    /**
     * RDP target options — screen 4d.
     *
     * Every boolean here binds into `options` and is written when the parent
     * form saves, so all of them are Checkboxes rather than Toggles.
     *
     * Two of the selects carry real security weight and now say so:
     *   - a TLS 1.0 security level is a downgrade to ciphers that are broken,
     *     not merely old
     *   - certificate verification is off by default for RDP because these
     *     servers almost always present self-signed certificates; that is a
     *     legitimate default and worth stating rather than leaving as an
     *     unexplained unchecked box
     */
    import {
        RdpTargetCompression,
        RdpTlsSecurity,
        type TargetOptionsTargetRdpOptions,
    } from 'admin/lib/api'
    import Callout from 'ui/Callout.svelte'
    import Checkbox from 'ui/Checkbox.svelte'
    import Input from 'ui/Input.svelte'
    import Select from 'ui/Select.svelte'

    interface Props {
        options: TargetOptionsTargetRdpOptions
    }

    let { options = $bindable() }: Props = $props()

    const SECURITY_LEVELS = [
        { value: RdpTlsSecurity.Tls12, label: 'Windows 2016 / 10+ (TLS 1.2)' },
        {
            value: RdpTlsSecurity.Tls12WithLegacyCiphers,
            label: 'Windows 2012 / 8+ (TLS 1.2 with legacy ciphers)',
        },
        {
            value: RdpTlsSecurity.Tls10Unsafe,
            label: 'Windows 2008 R2 or older (TLS 1.0, unsafe ciphers)',
        },
    ]

    const COMPRESSION = [
        { value: RdpTargetCompression.Lossless, label: 'Lossless' },
        { value: RdpTargetCompression.Remotefx, label: 'RemoteFX' },
    ]

    const unsafeTls = $derived(
        options.tlsSecurity === RdpTlsSecurity.Tls10Unsafe,
    )
</script>

<h5>Connection</h5>

<div class="row">
    <Input label="Target host" mono bind:value={options.host} />
    <Input
        label="Target port"
        type="number"
        mono
        class="port"
        value={String(options.port)}
        oninput={e => {
            const v = Number.parseInt((e.target as HTMLInputElement).value, 10)
            if (!Number.isNaN(v)) {
                options.port = v
            }
        }}
    />
</div>

<h5>Authentication</h5>

<div class="row">
    <Input label="Username" mono bind:value={options.username} />
    <Input label="Domain" mono hint="Optional." bind:value={options.domain} />
</div>

{#if options.auth.kind === 'Password'}
    <Input
        label="Password"
        type="password"
        autocomplete="off"
        bind:value={options.auth.password}
    />
{/if}

<div class="check">
    <Checkbox
        label="Interactive logon"
        hint="Shows the target's sign-in screen instead of logging on automatically. The credentials above are still used for network-level authentication."
        bind:checked={options.interactiveLogon}
    />
</div>

<h5>TLS</h5>

<Select
    label="Security level"
    options={SECURITY_LEVELS}
    bind:value={options.tlsSecurity}
/>

{#if unsafeTls}
    <Callout tone="warning" title="TLS 1.0 with unsafe ciphers">
        These ciphers are broken, not merely old — traffic to this target can be
        decrypted by anyone positioned on the path. Only select this for a host
        that genuinely cannot do better, and treat the segment it sits on as
        untrusted.
    </Callout>
{/if}

<div class="check">
    <Checkbox
        label="Verify certificate"
        hint="Off by default: RDP servers almost always present self-signed certificates, which verification would reject."
        bind:checked={options.verifyTls}
    />
</div>

<h5>Quality</h5>

<Select
    label="Compression between Warpgate and target"
    options={COMPRESSION}
    bind:value={options.compression}
    hint="If Warpgate and the RDP server share a network, lossless significantly improves image quality even for a remote client."
/>

<style>
    h5 {
        margin: var(--wg-space-xl) 0 var(--wg-space-md);
        font: var(--wg-text-label-md);
        color: var(--wg-text-muted);
    }

    h5:first-child {
        margin-top: 0;
    }

    .row {
        display: flex;
        flex-wrap: wrap;
        gap: var(--wg-space-lg);
        margin-bottom: var(--wg-space-lg);
    }

    .row > :global(*) {
        flex: 1 1 12rem;
        min-width: 0;
    }

    .row > :global(.port) {
        flex: 0 1 8rem;
    }

    .check {
        margin: var(--wg-space-md) 0 var(--wg-space-lg);
    }
</style>
