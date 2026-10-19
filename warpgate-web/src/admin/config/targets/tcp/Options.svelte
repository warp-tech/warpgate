<script lang="ts">
    import { FormGroup } from '@sveltestrap/sveltestrap'
    import type { TargetOptionsTargetTcpOptions } from 'admin/lib/api'

    interface Props {
        options: TargetOptionsTargetTcpOptions
    }

    let { options = $bindable() }: Props = $props()
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
