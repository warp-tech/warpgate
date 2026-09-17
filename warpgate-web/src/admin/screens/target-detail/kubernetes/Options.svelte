<script lang="ts">
    /**
     * Kubernetes target options — part of screen 4f.
     *
     * The certificate and private key use Textarea rather than Input,
     * deliberately: PEM blocks are multi-line and an operator needs to see
     * enough of one to confirm they pasted the right thing. They render in the
     * mono face for the same reason the rest of the machine data does.
     *
     * These were hand-rolled textareas when 4f landed. The fork check later
     * found the same markup and the same CSS in PublicKeyCredentialModal, so
     * both moved onto the ui/Textarea primitive.
     */
    import type { TargetOptionsTargetKubernetesOptions } from 'admin/lib/api'
    import { serverInfo } from 'gateway/lib/store'
    import Input from 'ui/Input.svelte'
    import Select from 'ui/Select.svelte'
    import Textarea from 'ui/Textarea.svelte'
    import TlsConfiguration from '../TlsConfiguration.svelte'

    interface Props {
        options: TargetOptionsTargetKubernetesOptions
    }

    let { options = $bindable() }: Props = $props()

    const authOptions = $derived([
        { value: 'Certificate', label: 'Client certificate' },
        { value: 'Token', label: 'Bearer token' },
        ...($serverInfo?.runningOnEc2
            ? [{ value: 'IamRole', label: 'IAM role (experimental)' }]
            : []),
    ])
</script>

<h5>Connection</h5>

<Input
    label="Cluster URL"
    mono
    placeholder="https://kubernetes.example.com:6443"
    bind:value={options.clusterUrl}
/>

<h5>Authentication</h5>

<Select
    label="Authentication type"
    options={authOptions}
    bind:value={options.auth.kind}
/>

{#if options.auth.kind === 'Certificate'}
    <div class="pem">
        <Textarea
            label="Client certificate"
            id="k8s-cert"
            rows={10}
            placeholder="-----BEGIN CERTIFICATE-----"
            bind:value={options.auth.certificate}
        />
    </div>
    <div class="pem">
        <Textarea
            label="Client private key"
            id="k8s-key"
            rows={7}
            placeholder="-----BEGIN RSA PRIVATE KEY-----"
            bind:value={options.auth.privateKey}
        />
    </div>
{/if}

{#if options.auth.kind === 'Token'}
    <Input
        label="Bearer token"
        type="password"
        autocomplete="off"
        mono
        bind:value={options.auth.token}
    />
{/if}

<h5>Transport</h5>

<TlsConfiguration bind:value={options.tls} subject="this cluster" />

<style>
    h5 {
        margin: var(--wg-space-xl) 0 var(--wg-space-md);
        font: var(--wg-text-label-md);
        color: var(--wg-text-muted);
    }

    h5:first-child {
        margin-top: 0;
    }

    .pem {
        margin-bottom: var(--wg-space-lg);
    }
</style>
