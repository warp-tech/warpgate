<script lang="ts">
    import { Alert, Badge, Button } from '@sveltestrap/sveltestrap'
    import {
        api,
        type CheckHealthResponse,
        type SecretBackendRequest,
        type SecretBackendResponse,
    } from 'admin/lib/api'
    import { adminPermissions } from 'admin/lib/store'
    import { stringifyError } from 'common/errors'
    import InfoBox from 'common/InfoBox.svelte'
    import { invalidateSecretBackends } from 'common/SecretRefInput.svelte'
    import SecretBackendModal from './SecretBackendModal.svelte'

    let error: string | undefined = $state()
    let backends: SecretBackendResponse[] | undefined = $state()
    let health: Record<string, CheckHealthResponse> = $state({})
    let modalOpen = $state(false)
    let editing: SecretBackendResponse | undefined = $state()

    async function load() {
        backends = await api.getSecretBackends()
        // Probes run in the background so a slow backend doesn't hold up the page.
        backends.forEach(backend => checkHealth(backend))
    }

    async function checkHealth(backend: SecretBackendResponse) {
        try {
            health[backend.id] = await api.checkSecretBackendHealth({ id: backend.id })
        } catch (e) {
            health[backend.id] = { health: 'error', error: await stringifyError(e) }
        }
    }

    load().catch(async e => {
        error = await stringifyError(e)
    })

    async function run(action: () => Promise<unknown>) {
        error = undefined
        try {
            await action()
            invalidateSecretBackends()
            await load()
        } catch (e) {
            error = await stringifyError(e)
        }
    }

    function openCreate() {
        editing = undefined
        modalOpen = true
    }

    function openEdit(backend: SecretBackendResponse) {
        editing = backend
        modalOpen = true
    }

    function save(request: SecretBackendRequest) {
        const backend = editing
        run(async () => {
            if (backend) {
                await api.updateSecretBackend({ id: backend.id, secretBackendRequest: request })
            } else {
                await api.createSecretBackend({ secretBackendRequest: request })
            }
        })
    }

    function remove(backend: SecretBackendResponse) {
        run(() => api.deleteSecretBackend({ id: backend.id }))
    }
</script>

<div class="page-summary-bar">
    <h1>Secret backends</h1>
    {#if $adminPermissions.configEdit}
        <Button class="ms-auto" color="primary" onclick={openCreate}>Add</Button>
    {/if}
</div>

{#if error}
    <Alert color="danger">{error}</Alert>
{/if}

<InfoBox>
    Target passwords and SSH keys can be a <code>vault://backend/path#field</code> reference,
    resolved from HashiCorp Vault or OpenBao when a connection is made. The path is the KV v2
    path without the <code>data/</code> segment.
</InfoBox>

{#if backends}
    {#if !backends.length}
        <p class="text-muted">No secret backends.</p>
    {/if}
    <div class="list-group list-group-flush">
        {#each backends as backend (backend.id)}
            {@const status = health[backend.id]}
            <div class="list-group-item px-0">
                <div class="d-flex align-items-center gap-2">
                    <strong>{backend.name}</strong>
                    <Badge color="secondary">{backend.backendType}</Badge>
                    {#if status?.health === 'ok'}
                        <Badge color="success">Healthy</Badge>
                    {:else if status}
                        <Badge color="danger" title={status.error ?? ''}>Unhealthy</Badge>
                    {/if}
                    <Button
                        class="ms-auto"
                        color="link px-0"
                        onclick={e => {
                            e.preventDefault()
                            checkHealth(backend)
                        }}
                    >
                        Check health
                    </Button>
                    {#if $adminPermissions.configEdit}
                        <Button
                            class="ms-3"
                            color="link px-0"
                            onclick={e => {
                                e.preventDefault()
                                openEdit(backend)
                            }}
                        >
                            Edit
                        </Button>
                        <Button
                            class="ms-3"
                            color="link px-0"
                            onclick={e => {
                                e.preventDefault()
                                remove(backend)
                            }}
                        >
                            Delete
                        </Button>
                    {/if}
                </div>
                <div class="text-muted small">
                    {backend.address}
                    {#if backend.namespace}
                        · namespace {backend.namespace}
                    {/if}
                    · {backend.authMethod}
                </div>
                {#if status?.health === 'error' && status.error}
                    <div class="text-danger small">{status.error}</div>
                {/if}
            </div>
        {/each}
    </div>
{/if}

{#if modalOpen}
    <SecretBackendModal bind:isOpen={modalOpen} instance={editing} {save} />
{/if}
