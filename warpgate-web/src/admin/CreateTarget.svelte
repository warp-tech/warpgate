<script lang="ts">
import { api, type TargetOptions, TlsMode } from 'admin/lib/api'
import AsyncButton from 'common/AsyncButton.svelte'
import { replace } from 'svelte-spa-router'
import { Alert, FormGroup } from '@sveltestrap/sveltestrap'

let error: Error|null = null
let name = ''
let type: 'Http' | 'MySql' | 'Ssh' = 'Ssh'

async function create () {
    if (!name || !type) {
        return
    }
    try {
        const options: TargetOptions|undefined = {
            Ssh: {
                kind: 'Ssh' as const,
                host: '192.168.0.1',
                port: 22,
                username: 'root',
                auth: {
                    kind: 'PublicKey' as const,
                },
            },
            Http: {
                kind: 'Http' as const,
                url: 'http://192.168.0.1',
                tls: {
                    mode: TlsMode.Preferred,
                    verify: true,
                },
            },
            MySql: {
                kind: 'MySql' as const,
                host: '192.168.0.1',
                port: 3306,
                tls: {
                    mode: TlsMode.Preferred,
                    verify: true,
                },
                username: 'root',
                password: '',
            },
        }[type]
        if (!options) {
            return
        }
        const target = await api.createTarget({
            targetDataRequest: {
                name,
                options,
            },
        })
        replace(`/targets/${target.id}`)
    } catch (err) {
        error = err as Error
    }
}

</script>

{#if error}
<Alert color="danger">{error}</Alert>
{/if}


<div class="page-summary-bar">
    <h1>Add a target</h1>
</div>

<FormGroup floating label="Name">
    <input class="form-control" bind:value={name} />
</FormGroup>

<FormGroup floating label="Type">
    <select bind:value={type} class="form-control">
        <option value={'Ssh'}>SSH</option>
        <option value={'Http'}>HTTP</option>
        <option value={'MySql'}>MySQL</option>
    </select>
</FormGroup>

<AsyncButton
    outline
    click={create}
>Create target</AsyncButton>
