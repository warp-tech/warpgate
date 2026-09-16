<script lang="ts">
    /**
     * HTTP target options — screen 4c.
     *
     * TLS lives here, with protocol context, per the earlier decision to drop
     * it from the Targets list: it is a per-protocol field inside the
     * TargetOptions union, not a uniform column.
     *
     * `externalHost` is normalised to undefined on save by the parent, which
     * is why an empty string here is fine.
     */
    import type { TargetOptionsTargetHTTPOptions } from 'admin/lib/api'
    import { serverInfo } from 'gateway/lib/store'
    import Input from 'ui/Input.svelte'
    import TlsConfiguration from '../TlsConfiguration.svelte'
    import HeadersEditor from './HeadersEditor.svelte'

    interface Props {
        options: TargetOptionsTargetHTTPOptions
    }

    let { options = $bindable() }: Props = $props()
</script>

<h5>Connection</h5>

<Input
    label="Target URL"
    mono
    placeholder="https://internal.example.com"
    bind:value={options.url}
/>

<TlsConfiguration bind:value={options.tls} subject="this target" />

{#if $serverInfo?.externalHost}
    <Input
        label="Bind to a domain"
        mono
        placeholder={`foo.${$serverInfo.externalHost}`}
        hint="Serve this target on its own hostname instead of a path under the portal."
        bind:value={options.externalHost}
    />
{/if}

<h5>Additional headers</h5>

<HeadersEditor bind:value={options.headers} />

<style>
    h5 {
        margin: var(--wg-space-xl) 0 var(--wg-space-md);
        font: var(--wg-text-label-md);
        color: var(--wg-text-muted);
    }

    h5:first-child {
        margin-top: 0;
    }
</style>
