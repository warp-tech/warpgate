<script lang="ts">
    import { FormGroup } from '@sveltestrap/sveltestrap'
    import type { TargetOptionsTargetOracleOptions } from 'admin/lib/api'
    import HelpText from 'admin/lib/HelpText.svelte'
    import { adminPermissions } from 'admin/lib/store'
    import SecretRefInput from 'common/SecretRefInput.svelte'
    import TlsConfiguration from '../../../TlsConfiguration.svelte'
    import TestConnection from './TestConnection.svelte'

    interface Props {
        id: string
        name: string
        options: TargetOptionsTargetOracleOptions
    }

    let { id, name, options = $bindable() }: Props = $props()
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

<FormGroup floating label="Service name">
    <input
        class="form-control"
        bind:value={options.serviceName}
        placeholder="FREEPDB1"
    >
</FormGroup>
<HelpText>
    Oracle TNS service name (<code>CONNECT_DATA</code>
    <code>SERVICE_NAME</code>) used to route the session to this target.
</HelpText>

<h4 class="mt-4">Authentication</h4>

<FormGroup floating label="Username">
    <input class="form-control" bind:value={options.username}>
</FormGroup>

{#if options.auth.kind === 'Password'}
    <SecretRefInput
        bind:value={options.auth.password}
        inlineLabel="Password"
        disabled={!$adminPermissions.targetsEdit}
        intendedUsage={{
            kind: 'Target',
            id,
            name,
        }}
    />
{/if}

{#if $adminPermissions.targetsEdit}
    <div class="mb-1 mt-3">
        <TestConnection {id} {options} />
    </div>
    <HelpText>
        Checks that Warpgate can reach the database, complete TLS, resolve the
        service name, and authenticate with the target's credentials. Tests the
        saved target, so save your changes first.
    </HelpText>
{/if}

<h4 class="mt-4">TLS</h4>
<TlsConfiguration bind:value={options.tls} />
<HelpText>
    With TLS enabled, Warpgate connects to the target over TCPS and the
    connection instructions tell clients to use TCPS too; otherwise both use
    plain TCP.
</HelpText>

<h4 class="mt-4">Advanced</h4>
<FormGroup floating label="Idle timeout">
    <input
        class="form-control"
        type="text"
        placeholder="10m"
        bind:value={options.idleTimeout}
        title="Human-readable duration (e.g., '30m', '1h', '2h30m'). Default: 10m"
    >
    <small class="form-text text-muted">
        How long an authenticated session can remain idle before requiring
        re-authentication. Examples: 30m, 1h, 2h30m. Leave empty for default
        (10m).
    </small>
</FormGroup>
