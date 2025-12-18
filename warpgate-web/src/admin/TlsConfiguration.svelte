<script lang="ts">
    import { type Tls, TlsMode } from 'admin/lib/api'
    import { FormGroup, Input } from '@sveltestrap/sveltestrap'

    interface Props {
        value: Tls
        class?: string
    }

    // eslint-disable-next-line svelte/no-unused-props
    let {
        value = $bindable(),
        'class': className = '',
    }: Props = $props()
</script>

<div class="row align-items-center {className}">
    <div class="col">
        <FormGroup floating label="TLS mode">
            <select bind:value={value.mode} class="form-control">
                <option value={TlsMode.Required}>Required</option>
                <option value={TlsMode.Preferred}>Preferred</option>
                <option value={TlsMode.Disabled}>Disabled</option>
            </select>
        </FormGroup>
    </div>
    {#if value.mode !== TlsMode.Disabled}
        <div class="col mb-3">
            <Input class="ms-3" type="switch" label="Verify certificate" bind:checked={value.verify} />
        </div>
    {/if}
</div>
