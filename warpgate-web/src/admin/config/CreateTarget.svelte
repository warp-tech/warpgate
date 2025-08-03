<script lang="ts">
    import { api, type TargetOptions, TlsMode } from 'admin/lib/api'
    import { replace } from 'svelte-spa-router'
    import { Button, ButtonGroup, Form, FormGroup } from '@sveltestrap/sveltestrap'
    import { stringifyError } from 'common/errors'
    import Alert from 'common/sveltestrap-s5-ports/Alert.svelte'
    import RadioButton from 'common/RadioButton.svelte'

    let error: string|null = $state(null)
    let name = $state('')
    let type: 'Ssh' | 'Http' | 'MySql' | 'Postgres' | 'Kubernetes' | 'WebAdmin' = $state('Ssh')

    async function create () {
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
                Postgres: {
                    kind: 'Postgres' as const,
                    host: '192.168.0.1',
                    port: 5432,
                    tls: {
                        mode: TlsMode.Preferred,
                        verify: true,
                    },
                    username: 'postgres',
                    password: '',
                },
                Kubernetes: {
                    kind: 'Kubernetes' as const,
                    clusterUrl: 'https://kubernetes.example.com:6443',
                    namespace: 'default',
                    tls: {
                        mode: TlsMode.Preferred,
                        verify: true,
                    },
                    auth: {
                        kind: 'Certificate' as const,
                        certificate: '',
                        privateKey: '',
                    },
                },
                WebAdmin: null as any,
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
            replace(`/config/targets/${target.id}`)
        } catch (err) {
            error = await stringifyError(err)
        }
    }

    const kinds: { name: string, value: 'Ssh' | 'Http' | 'MySql' | 'Postgres' | 'Kubernetes' }[] = [
        { name: 'SSH', value: 'Ssh' },
        { name: 'HTTP', value: 'Http' },
        { name: 'MySQL', value: 'MySql' },
        { name: 'PostgreSQL', value: 'Postgres' },
        { name: 'Kubernetes', value: 'Kubernetes' },
    ]
</script>

<div class="container-max-md">
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
            <!-- Defualt button for key handling -->
            <Button class="d-none" type="submit"></Button>

            <!-- svelte-ignore a11y_label_has_associated_control -->
            <label class="mb-2">Type</label>
            <ButtonGroup class="w-100 mb-3">
                {#each kinds as kind (kind.value)}
                    <RadioButton
                        label={kind.name}
                        value={kind.value}
                        bind:group={type}
                    />
                {/each}
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
</div>
