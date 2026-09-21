<script lang="ts">
    import { FormGroup } from '@sveltestrap/sveltestrap'
    import type { TargetOptionsTargetVncOptions } from 'admin/lib/api'
    import SecretRefInput from 'common/SecretRefInput.svelte'

    interface Props {
        id: string
        name: string
        options: TargetOptionsTargetVncOptions
    }

    let { id, name, options = $bindable() }: Props = $props()

    function setAuthKind(kind: 'None' | 'Password') {
        if (kind === 'Password') {
            options.auth = { kind: 'Password', password: '' }
        } else {
            options.auth = { kind: 'None' }
        }
    }
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

<FormGroup floating label="Authentication type">
    <select
        class="form-control"
        value={options.auth.kind}
        onchange={e => setAuthKind((e.currentTarget as HTMLSelectElement).value as 'None' | 'Password')}
    >
        <option value="None">None</option>
        <option value="Password">Password</option>
    </select>
</FormGroup>

{#if options.auth.kind === 'Password'}
    <SecretRefInput
        bind:value={options.auth.password}
        inlineLabel="Password"
        intendedUsage={{
            kind: 'Target',
            id,
            name
        }}
    />
{/if}
