<script lang="ts">
    /**
     * Kubernetes target options — part of screen 4f.
     *
     * The certificate and private key are textareas rather than Input,
     * deliberately: PEM blocks are multi-line and an operator needs to see
     * enough of one to confirm they pasted the right thing. They render in the
     * mono face for the same reason the rest of the machine data does.
     */
    import type { TargetOptionsTargetKubernetesOptions } from 'admin/lib/api'
    import { serverInfo } from 'gateway/lib/store'
    import Input from 'ui/Input.svelte'
    import Select from 'ui/Select.svelte'
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
        <label for="k8s-cert">Client certificate</label>
        <textarea
            id="k8s-cert"
            rows="10"
            spellcheck="false"
            placeholder="-----BEGIN CERTIFICATE-----"
            bind:value={options.auth.certificate}
        ></textarea>
    </div>
    <div class="pem">
        <label for="k8s-key">Client private key</label>
        <textarea
            id="k8s-key"
            rows="7"
            spellcheck="false"
            placeholder="-----BEGIN RSA PRIVATE KEY-----"
            bind:value={options.auth.privateKey}
        ></textarea>
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
        display: flex;
        flex-direction: column;
        gap: var(--wg-space-xs);
        margin-bottom: var(--wg-space-lg);
    }

    .pem label {
        font: var(--wg-text-body-md);
        color: var(--wg-text-muted);
    }

    textarea {
        width: 100%;
        padding: var(--wg-space-sm);
        background: var(--wg-surface-sunken);
        border: var(--wg-border-width) solid var(--wg-border-strong);
        border-radius: var(--wg-radius-control);
        color: var(--wg-text);
        font: var(--wg-text-code-sm);
        resize: vertical;
    }

    textarea:focus-visible {
        outline: var(--wg-focus-ring);
        outline-offset: var(--wg-focus-ring-offset);
        border-color: var(--wg-primary);
    }

    textarea::placeholder {
        color: var(--wg-text-subtle);
    }
</style>
