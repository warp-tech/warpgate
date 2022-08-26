<script lang="ts">
import { api, TargetOptions, TlsMode } from 'admin/lib/api'
import AsyncButton from 'common/AsyncButton.svelte'
import { push } from 'svelte-spa-router'
import { Alert, FormGroup } from 'sveltestrap'

let error: Error|null = null
let name = ''
let type: 'Ssh'|'MySql'|'Http' = 'Ssh'

async function create () {
    if (!name || !type) {
        return
    }
    try {
        const options: TargetOptions|undefined = {
            Ssh: {
                kind: 'Ssh',
                host: '192.168.0.1',
                port: 22,
                username: 'root',
                auth: {
                    kind: 'PublicKey',
                },
            } as TargetOptions,
            Http: {
                kind: 'Http',
                url: 'http://192.168.0.1',
                tls: {
                    mode: TlsMode.Preferred,
                    verify: true,
                },
            } as TargetOptions,
            MySql: {
                kind: 'MySql',
                host: '192.168.0.1',
                port: 3306,
                tls: {
                    mode: TlsMode.Preferred,
                    verify: true,
                },
                username: 'root',
                password: '',
            } as TargetOptions,
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
        console.log(target)
        push(`/targets`)
    } catch (err) {
        error = err
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
