<script lang="ts">
    import {
        api,
        type SSHClientKey,
        type SSHClientKeyKind,
        type SSHKnownHost,
    } from 'admin/lib/api'
    import { adminPermissions } from 'admin/lib/store'
    import CopyableTextArea from 'common/CopyableTextArea.svelte'
    import { stringifyError } from 'common/errors'
    import InfoBox from 'common/InfoBox.svelte'
    import Badge from 'ui/Badge.svelte'
    import Button from 'ui/Button.svelte'
    import Callout from 'ui/Callout.svelte'
    import ClientKeyModal from './ClientKeyModal.svelte'
    import GenerateClientKeyModal from './GenerateClientKeyModal.svelte'

    let error: string | undefined = $state()
    let knownHosts: SSHKnownHost[] | undefined = $state()
    let clientKeys: SSHClientKey[] | undefined = $state()
    let keyModalOpen = $state(false)
    let editingKey: SSHClientKey | undefined = $state()
    let generateModalOpen = $state(false)

    async function load() {
        clientKeys = await api.getSshOwnKeys()
        if ($adminPermissions.configEdit) {
            knownHosts = await api.getSshKnownHosts()
        }
    }

    load().catch(async e => {
        error = await stringifyError(e)
    })

    async function run(action: () => Promise<unknown>) {
        error = undefined
        try {
            await action()
            await load()
        } catch (e) {
            error = await stringifyError(e)
        }
    }

    function openImportKey() {
        editingKey = undefined
        keyModalOpen = true
    }

    function openEditKey(key: SSHClientKey) {
        editingKey = key
        keyModalOpen = true
    }

    function saveKey(label: string, secretKey: string, isDefault: boolean) {
        const key = editingKey
        run(async () => {
            if (key) {
                await api.updateSshOwnKey({
                    id: key.id,
                    updateSSHClientKeyRequest: { label, isDefault },
                })
                return
            }
            await api.importSshOwnKey({
                importSSHClientKeyRequest: { label, secretKey, isDefault },
            })
        })
    }

    function generateKey(label: string, kind: SSHClientKeyKind) {
        run(async () => {
            await api.generateSshOwnKey({
                generateSSHClientKeyRequest: { label, kind },
            })
        })
    }

    async function deleteKey(key: SSHClientKey) {
        await run(() => api.deleteSshOwnKey(key))
    }

    async function deleteHost(host: SSHKnownHost) {
        await run(() => api.deleteSshKnownHost(host))
    }
</script>

<div class="page-summary-bar">
    <h1>SSH keys</h1>
    <div class="d-flex gap-2 ms-auto">
        {#if $adminPermissions.configEdit}
            <Button
                variant="primary"
                onclick={() => (generateModalOpen = true)}
            >
                Generate
            </Button>
            <Button variant="secondary" onclick={openImportKey}>
                Import
            </Button>
        {/if}
    </div>
</div>

{#if error}
    <Callout tone="danger" title="Something went wrong">{error}</Callout>
{/if}

{#if clientKeys}
    <InfoBox>
        Add one of these keys to the targets'
        <code>authorized_keys</code>
        files
    </InfoBox>

    <div class="list-group list-group-flush">
        {#each clientKeys as key (key.id)}
            <div class="list-group-item px-0">
                <div class="d-flex align-items-center gap-2">
                    <strong>{key.label}</strong>
                    {#if key.isDefault}
                        <Badge tone="primary">Default</Badge>
                    {/if}
                    {#if $adminPermissions.configEdit}
                        <Button
                            class="ms-auto"
                            variant="ghost"
                            onclick={e => {
                                e.preventDefault()
                                openEditKey(key)
                            }}
                        >
                            Edit
                        </Button>
                        <Button
                            class="ms-3"
                            variant="ghost"
                            onclick={e => {
                                e.preventDefault()
                                deleteKey(key)
                            }}
                        >
                            Delete
                        </Button>
                    {/if}
                </div>
                <CopyableTextArea label="Public key" value={key.publicKey} />
            </div>
        {/each}
    </div>
{/if}

{#if keyModalOpen}
    <ClientKeyModal
        bind:isOpen={keyModalOpen}
        instance={editingKey}
        save={saveKey}
    />
{/if}

{#if generateModalOpen}
    <GenerateClientKeyModal
        bind:isOpen={generateModalOpen}
        save={generateKey}
    />
{/if}

<div class="mb-3"></div>
{#if knownHosts}
    {#if knownHosts.length}
        <h2>Known hosts: {knownHosts.length}</h2>
    {:else}
        <h2>No known hosts</h2>
    {/if}
    <div class="list-group list-group-flush">
        {#each knownHosts as host (host.id)}
            <div class="list-group-item">
                <div class="d-flex">
                    <strong> {host.host}:{host.port} </strong>

                    <Button
                        class="ms-auto"
                        variant="ghost"
                        onclick={e => {
                            e.preventDefault()
                            deleteHost(host)
                        }}
                        disabled={!$adminPermissions.configEdit}
                    >
                        Delete
                    </Button>
                </div>
                <pre>{host.keyType} {host.keyBase64}</pre>
            </div>
        {/each}
    </div>
{/if}

<style lang="scss">
    pre {
        word-break: break-word;
        white-space: normal;
    }
</style>
