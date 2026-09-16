<script lang="ts">
    /**
     * MySQL and PostgreSQL target options — part of screen 4f.
     *
     * These were inline in the old Target.svelte rather than a component; the
     * two protocols share every field except the Postgres-only protocol
     * version and idle timeout, which live in the Advanced section on the
     * parent page.
     *
     * TlsConfiguration is reused from 4c, which is why this file is short.
     */
    import type {
        TargetOptionsTargetMySqlOptions,
        TargetOptionsTargetPostgresOptions,
    } from 'admin/lib/api'
    import { serverInfo } from 'gateway/lib/store'
    import Input from 'ui/Input.svelte'
    import Select from 'ui/Select.svelte'
    import TlsConfiguration from '../TlsConfiguration.svelte'

    interface Props {
        options:
            | TargetOptionsTargetMySqlOptions
            | TargetOptionsTargetPostgresOptions
    }

    let { options = $bindable() }: Props = $props()

    const authOptions = $derived([
        { value: 'Password', label: 'Password' },
        ...($serverInfo?.runningOnEc2
            ? [{ value: 'IamRole', label: 'IAM role (experimental)' }]
            : []),
    ])
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
    {#if options.auth}
        <Select
            label="Authenticate using"
            options={authOptions}
            bind:value={options.auth.kind}
        />
    {/if}
</div>

{#if options.auth?.kind === 'Password'}
    <Input
        label="Password"
        type="password"
        autocomplete="off"
        bind:value={options.auth.password}
    />
{/if}

<h5>Transport</h5>

<TlsConfiguration bind:value={options.tls} subject="this database" />

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
