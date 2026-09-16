<script lang="ts">
    /**
     * VNC target options — screen 4e.
     *
     * `setAuthKind` replaces the whole auth object rather than mutating a
     * `kind` field, because the two variants carry different shapes — the
     * password only exists on one of them. Preserved verbatim.
     */
    import type { TargetOptionsTargetVncOptions } from 'admin/lib/api'
    import Callout from 'ui/Callout.svelte'
    import Input from 'ui/Input.svelte'
    import Select from 'ui/Select.svelte'

    interface Props {
        options: TargetOptionsTargetVncOptions
    }

    let { options = $bindable() }: Props = $props()

    function setAuthKind(kind: 'None' | 'Password') {
        if (kind === 'Password') {
            options.auth = { kind: 'Password', password: '' }
        } else {
            options.auth = { kind: 'None' }
        }
    }

    const AUTH_KINDS = [
        { value: 'None', label: 'None' },
        { value: 'Password', label: 'Password' },
    ]
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

<Select
    label="Authentication type"
    options={AUTH_KINDS}
    value={options.auth.kind}
    onchange={e =>
        setAuthKind(
            (e.target as HTMLSelectElement).value as 'None' | 'Password',
        )}
/>

{#if options.auth.kind === 'Password'}
    <Input
        label="Password"
        type="password"
        autocomplete="off"
        bind:value={options.auth.password}
    />
{:else}
    <Callout tone="warning" title="This target accepts unauthenticated VNC">
        Anyone who can reach the target through Warpgate gets a desktop session
        without presenting a VNC password. Warpgate's own authentication and
        role checks still apply; the target itself has none.
    </Callout>
{/if}

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
</style>
