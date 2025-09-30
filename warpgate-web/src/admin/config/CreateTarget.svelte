<script lang="ts">
    import { api, type TargetOptions, type TargetGroup, TlsMode } from 'admin/lib/api'
    import { replace } from 'svelte-spa-router'
    import { Button, ButtonGroup, Form, FormGroup } from '@sveltestrap/sveltestrap'
    import { stringifyError } from 'common/errors'
    import Alert from 'common/sveltestrap-s5-ports/Alert.svelte'
    import { TargetKind } from 'gateway/lib/api'
    import RadioButton from 'common/RadioButton.svelte'
    import { onMount } from 'svelte'

    let error: string|null = $state(null)
    let name = $state('')
    let type: TargetKind = $state(TargetKind.Ssh)
    let groups: TargetGroup[] = $state([])
    let selectedGroupId: string | undefined = $state()

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
                    groupId: selectedGroupId,
                },
            })
            replace(`/config/targets/${target.id}`)
        } catch (err) {
            error = await stringifyError(err)
        }
    }

    onMount(async () => {
        try {
            groups = await api.listTargetGroups()
        } catch (e) {
            console.error('Failed to load target groups:', e)
        }
    })

    const kinds: { name: string, value: TargetKind }[] = [
        { name: 'SSH', value: TargetKind.Ssh },
        { name: 'HTTP', value: TargetKind.Http },
        { name: 'MySQL', value: TargetKind.MySql },
        { name: 'PostgreSQL', value: TargetKind.Postgres },
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

            <FormGroup floating label="Group">
                <select class="form-control" bind:value={selectedGroupId}>
                    <option value={undefined}>No group</option>
                    {#each groups as group}
                        <option value={group.id}>{group.name}</option>
                    {/each}
                </select>
            </FormGroup>

            <Button
                color="primary"
                type="submit"
            >Create target</Button>
        </Form>
    </div>
</div>
