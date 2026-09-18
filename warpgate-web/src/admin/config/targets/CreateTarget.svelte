<script lang="ts">
    import Button from 'ui/Button.svelte'
    import Callout from 'ui/Callout.svelte'
    import Input from 'ui/Input.svelte'
    import 'ui/layout.css'
    import {
        api,
        RdpTargetCompression,
        RdpTlsSecurity,
        type TargetGroup,
        type TargetOptions,
        TlsMode,
    } from 'admin/lib/api'
    import { adminPermissions } from 'admin/lib/store'
    import { stringifyError } from 'common/errors'
    import { TargetKind } from 'gateway/lib/api'
    import { onMount } from 'svelte'
    import { replace } from 'svelte-spa-router'
    import Select from 'ui/Select.svelte'

    interface Props {
        params: { kind: string }
    }

    let { params }: Props = $props()

    let error: string | null = $state(null)
    let name = $state('')
    let groups: TargetGroup[] = $state([])
    // ui/Select carries strings, so "no group" is '' here and is converted
    // back to undefined at submit — the API distinguishes the two.
    let selectedGroupId = $state('')

    async function create() {
        try {
            const options: TargetOptions | undefined = {
                Ssh: {
                    kind: TargetKind.Ssh,
                    host: '192.168.0.1',
                    port: 22,
                    username: 'root',
                    allowInsecureAlgos: false,
                    auth: {
                        kind: 'PublicKey' as const,
                    },
                },
                Http: {
                    kind: TargetKind.Http,
                    url: 'http://192.168.0.1',
                    tls: {
                        mode: TlsMode.Preferred,
                        verify: true,
                    },
                    headers: {},
                },
                MySql: {
                    kind: TargetKind.MySql,
                    host: '192.168.0.1',
                    port: 3306,
                    tls: {
                        mode: TlsMode.Preferred,
                        verify: true,
                    },
                    username: 'root',
                    auth: {
                        kind: 'Password' as const,
                        password: '',
                    },
                },
                Postgres: {
                    kind: TargetKind.Postgres,
                    host: '192.168.0.1',
                    port: 5432,
                    tls: {
                        mode: TlsMode.Preferred,
                        verify: true,
                    },
                    username: 'postgres',
                    protocolVersion: '3.2' as const,
                    auth: {
                        kind: 'Password' as const,
                        password: '',
                    },
                },
                Kubernetes: {
                    kind: TargetKind.Kubernetes,
                    clusterUrl: 'https://kubernetes.example.com:6443',
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
                Vnc: {
                    kind: TargetKind.Vnc,
                    host: '192.168.0.1',
                    port: 5900,
                    auth: {
                        kind: 'None' as const,
                    },
                },
                Rdp: {
                    kind: TargetKind.Rdp,
                    host: '192.168.0.1',
                    port: 3389,
                    username: 'Administrator',
                    auth: {
                        kind: 'Password' as const,
                        password: '',
                    },
                    verifyTls: false,
                    interactiveLogon: false,
                    tlsSecurity: RdpTlsSecurity.Tls12,
                    compression: RdpTargetCompression.Remotefx,
                },
            }[params.kind]
            if (!options) {
                return
            }
            const target = await api.createTarget({
                targetDataRequest: {
                    name,
                    options,
                    groupId: selectedGroupId || undefined,
                    requireApproval: false,
                    ticketRequestsDisabled: false,
                    ticketRequireApproval: false,
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
        } catch (err) {
            error = await stringifyError(err)
        }
    })
</script>

<div class="wg-page-narrow">
    <div class="wg-page-head">
        <h1>Add a target</h1>
    </div>

    {#if !$adminPermissions.targetsCreate}
        <div class="notice">
            <Callout tone="warning" title="Not available to your role">
                You do not have permission to create targets.
            </Callout>
        </div>
    {/if}

    {#if error}
        <div class="notice">
            <Callout tone="danger" title="Could not create the target">
                {error}
            </Callout>
        </div>
    {/if}

    <form
        class="wg-field-stack"
        onsubmit={e => {
            e.preventDefault()
            create()
        }}
    >
        <Input label="Name" required autofocus bind:value={name} />

        {#if groups.length > 0}
            <Select
                label="Group"
                bind:value={selectedGroupId}
                options={[
                    { value: '', label: 'No group' },
                    ...groups.map(g => ({ value: g.id, label: g.name })),
                ]}
            />
        {/if}

        <div class="actions">
            <Button
                variant="primary"
                type="submit"
                disabled={!$adminPermissions.targetsCreate || !name.trim()}
                click={create}
            >
                Create target
            </Button>
        </div>
    </form>
</div>

<style>
    .notice {
        margin-bottom: var(--wg-space-lg);
    }

    .actions {
        display: flex;
        justify-content: flex-end;
    }
</style>
