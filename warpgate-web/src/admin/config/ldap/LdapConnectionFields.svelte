<script lang="ts">
    import { FormGroup, Input } from '@sveltestrap/sveltestrap'
    import TlsConfiguration from 'admin/TlsConfiguration.svelte'
    import type { Tls } from 'admin/lib/api'

    interface Props {
        host: string
        port: number
        bindDn: string
        bindPassword: string
        tls: Tls
        userFilter: string
        passwordPlaceholder?: string
        passwordRequired?: boolean
    }

    let {
        host = $bindable(),
        port = $bindable(),
        bindDn = $bindable(),
        bindPassword = $bindable(),
        tls = $bindable(),
        userFilter = $bindable(),
        passwordPlaceholder = undefined,
        passwordRequired = true,
    }: Props = $props()
</script>

<div class="mt-4">
    <div class="row">
        <div class="col-md-8 d-flex align-items-center gap-3">
            <FormGroup floating label="Host" class="flex-grow-1">
                <Input bind:value={host} required />
            </FormGroup>
        </div>
        <div class="col-md-4">
            <FormGroup floating label="Port">
                <Input bind:value={port} type="number" required />
            </FormGroup>
        </div>
    </div>
    <TlsConfiguration bind:value={tls} class="flex-grow-1" />
</div>

<div class="mt-4 row">
    <div class="col-md-6">
        <FormGroup floating label="Bind username / DN">
            <Input
                bind:value={bindDn}
                required
            />
        </FormGroup>
    </div>
    <div class="col-md-6">
        <FormGroup floating label="Bind password">
            <Input
                type="password"
                bind:value={bindPassword}
                placeholder={passwordPlaceholder}
                required={passwordRequired}
            />
        </FormGroup>
    </div>
</div>

<div class="mt-4">
    <FormGroup floating label="User query filter">
        <Input
            bind:value={userFilter}
        />
    </FormGroup>
</div>
