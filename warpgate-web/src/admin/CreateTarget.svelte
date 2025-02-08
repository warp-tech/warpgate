<script lang="ts">
    import { api, type TargetOptions, TlsMode } from 'admin/lib/api'
    import AsyncButton from 'common/AsyncButton.svelte'
    import { replace } from 'svelte-spa-router'
    import { Button, ButtonGroup, Form, FormGroup } from '@sveltestrap/sveltestrap'
    import { stringifyError } from 'common/errors'
    import Alert from 'common/sveltestrap-s5-ports/Alert.svelte'
    import { TargetKind } from 'gateway/lib/api'

    let error: string|null = $state(null)
    let name = $state('')
    let type: TargetKind = $state(TargetKind.Ssh)

    async function create () {
        try {
            const options: TargetOptions|undefined = {
                [TargetKind.Ssh]: {
                    kind: TargetKind.Ssh,
                    host: '192.168.0.1',
                    port: 22,
                    username: 'root',
                    auth: {
                        kind: 'PublicKey' as const,
                    },
                },
                [TargetKind.Http]: {
                    kind: TargetKind.Http,
                    url: 'http://192.168.0.1',
                    tls: {
                        mode: TlsMode.Preferred,
                        verify: true,
                    },
                },
                [TargetKind.MySql]: {
                    kind: TargetKind.MySql,
                    host: '192.168.0.1',
                    port: 3306,
                    tls: {
                        mode: TlsMode.Preferred,
                        verify: true,
                    },
                    username: 'root',
                    password: '',
                },
                [TargetKind.Postgres]: {
                    kind: TargetKind.Postgres,
                    host: '192.168.0.1',
                    port: 5432,
                    tls: {
                        mode: TlsMode.Preferred,
                        verify: true,
                    },
                    username: 'postgres',
                    password: '',
                },
                [TargetKind.WebAdmin]: null as any,
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
            error = await stringifyError(err)
        }
    }

</script>

{#if error}
<Alert color="danger">{error}</Alert>
{/if}


<div class="page-summary-bar">
    <h1>add a target</h1>
</div>

<div class="narrow-page">
    <Form on:submit={e => {
        create()
        e.preventDefault()
    }}>
        <!-- svelte-ignore a11y_label_has_associated_control -->
        <label class="mb-2">Type</label>
        <ButtonGroup class="w-100 mb-3">
            <Button
                active={type === TargetKind.Ssh}
                on:click={() => type = TargetKind.Ssh}
            >SSH</Button>
            <Button
                active={type === TargetKind.Http}
                on:click={() => type = TargetKind.Http}
            >HTTP</Button>
            <Button
                active={type === TargetKind.MySql}
                on:click={() => type = TargetKind.MySql}
            >MySQL</Button>
            <Button
                active={type === TargetKind.Postgres}
                on:click={() => type = TargetKind.Postgres}
            >PostgreSQL</Button>
        </ButtonGroup>

        <FormGroup floating label="Name">
            <input class="form-control" required bind:value={name} />
        </FormGroup>

        <Button
            color="primary"
            type="submit"
        >Create target</Button>
    </Form>
</div>
