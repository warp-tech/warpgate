<script lang="ts">
    import { Alert, Button, FormGroup } from '@sveltestrap/sveltestrap'
    import { api, type SSHClientKey, type SSHKnownHost } from 'admin/lib/api'
    import { adminPermissions } from 'admin/lib/store'
    import AsyncButton from 'common/AsyncButton.svelte'
    import CopyableTextArea from 'common/CopyableTextArea.svelte'
    import { stringifyError } from 'common/errors'

    let error: string | undefined = $state()
    let knownHosts: SSHKnownHost[] | undefined = $state()
    let clientKeys: SSHClientKey[] | undefined = $state()
    let importLabel = $state('')
    let importSecretKey = $state('')

    async function load() {
        clientKeys = await api.getSshClientKeys()
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

    async function importKey() {
        await run(async () => {
            await api.importSshClientKey({
                importSSHClientKeyRequest: {
                    label: importLabel,
                    secretKey: importSecretKey,
                },
            })
            importLabel = ''
            importSecretKey = ''
        })
    }

    async function makeDefault(key: SSHClientKey) {
        await run(() =>
            api.updateSshClientKey({
                id: key.id,
                updateSSHClientKeyRequest: {
                    label: key.label,
                    isDefault: true,
                },
            }),
        )
    }

    async function deleteKey(key: SSHClientKey) {
        await run(() => api.deleteSshClientKey(key))
    }

    async function deleteHost(host: SSHKnownHost) {
        await run(() => api.deleteSshKnownHost(host))
    }
</script>

<div class="page-summary-bar">
    <h1>SSH</h1>
</div>

{#if error}
    <Alert color="danger">{error}</Alert>
{/if}

{#if clientKeys}
    <h2>Warpgate's own SSH keys</h2>
    <Alert color="info"
        >Add these keys to the targets'
        <code>authorized_keys</code>
        files</Alert
    >
    <div class="list-group list-group-flush">
        {#each clientKeys as key (key.id)}
            <div class="list-group-item px-0">
                <div class="d-flex align-items-center">
                    <strong>{key.label}</strong>
                    <span class="text-muted ms-2">{key.kind}</span>
                    {#if key.isDefault}
                        <span class="ms-2">(default)</span>
                    {/if}
                    {#if $adminPermissions.configEdit && !key.isDefault}
                        <Button
                            class="ms-auto"
                            color="link px-0"
                            onclick={e => {
                                e.preventDefault()
                                makeDefault(key)
                            }}
                            >Make default</Button
                        >
                        <Button
                            class="ms-3"
                            color="link px-0"
                            onclick={e => {
                                e.preventDefault()
                                deleteKey(key)
                            }}
                            >Delete</Button
                        >
                    {/if}
                </div>
                <CopyableTextArea label="Public key" value={key.publicKey} />
            </div>
        {/each}
    </div>

    {#if $adminPermissions.configEdit}
        <h3 class="mt-4">Import a key</h3>
        <FormGroup floating label="Label">
            <input class="form-control" bind:value={importLabel} required>
        </FormGroup>
        <FormGroup
            floating
            label="Private key (OpenSSH or PKCS#8 PEM, no passphrase)"
        >
            <textarea
                class="form-control font-monospace"
                style="height: 10rem"
                bind:value={importSecretKey}
                required
            ></textarea>
        </FormGroup>
        <AsyncButton
            color="primary"
            disabled={!importLabel || !importSecretKey}
            click={importKey}
            >Import</AsyncButton
        >
    {/if}
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
                        color="link px-0"
                        onclick={e => {
                            e.preventDefault()
                            deleteHost(host)
                        }}
                        disabled={!$adminPermissions.configEdit}
                        >Delete</Button
                    >
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
