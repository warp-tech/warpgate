<script lang="ts">
    import { Alert, Badge, Button } from '@sveltestrap/sveltestrap'
    import {
        api,
        type CheckHealthResponse,
        type SecretBackend,
        type SecretBackendRequest,
    } from 'admin/lib/api'
    import { adminPermissions } from 'admin/lib/store'
    import EmptyState from 'common/EmptyState.svelte'
    import { stringifyError } from 'common/errors'
    import ItemList, { type PaginatedResponse } from 'common/ItemList.svelte'
    import { invalidateSecretBackends } from 'common/SecretRefInput.svelte'
    import { from, map, type Observable } from 'rxjs'
    import { SvelteMap } from 'svelte/reactivity'
    import firstBy from 'thenby'
    import SecretBackendModal from './SecretBackendModal.svelte'

    let error: string | undefined = $state()
    let health = new SvelteMap<string, CheckHealthResponse>()
    let modalOpen = $state(false)
    let editing: SecretBackend | undefined = $state()
    let gen = $state(0)

    function load(): Observable<PaginatedResponse<SecretBackend>> {
        return from(api.getSecretBackends()).pipe(
            map(items => {
                for (const b of items) {
                    checkHealth(b)
                }
                const sorted = items.sort(firstBy(x => x.name))
                return {
                    items: sorted,
                    offset: 0,
                    total: sorted.length,
                }
            }),
        )
    }

    async function checkHealth(backend: SecretBackend) {
        try {
            health.set(
                backend.id,
                await api.checkSecretBackendHealth({
                    id: backend.id,
                }),
            )
        } catch (e) {
            health.set(backend.id, { error: await stringifyError(e) })
        }
    }

    async function runAndInvalidate(action: () => Promise<unknown>) {
        error = undefined
        try {
            await action()
            invalidateSecretBackends()
        } catch (e) {
            error = await stringifyError(e)
        }
    }

    function openCreate() {
        editing = undefined
        modalOpen = true
    }

    function openEdit(backend: SecretBackend) {
        editing = backend
        modalOpen = true
    }

    function save(request: SecretBackendRequest) {
        const backend = editing
        runAndInvalidate(async () => {
            if (backend) {
                await api.updateSecretBackend({
                    id: backend.id,
                    secretBackendRequest: request,
                })
            } else {
                await api.createSecretBackend({ secretBackendRequest: request })
            }
            gen++
        })
    }

    async function remove(backend: SecretBackend) {
        if (!confirm('Delete this secret backend?')) {
            return
        }
        await runAndInvalidate(() =>
            api.deleteSecretBackend({ id: backend.id }),
        )
        gen++
    }
</script>

<div class="page-summary-bar">
    <h1>Secret backends</h1>
    {#if $adminPermissions.configEdit}
        <Button class="ms-auto" color="primary" onclick={openCreate}>
            Add a secret backend
        </Button>
    {/if}
</div>

{#if error}
    <Alert color="danger">{error}</Alert>
{/if}

{#key gen}
    <ItemList {load} showSearch={false}>
        {#snippet item(backend)}
            {const probe = $derived(health.get(backend.id))}
            <div class="list-group-item px-0">
                <div class="d-flex align-items-center gap-2">
                    <strong>{backend.name}</strong>
                    <Badge color="secondary">{backend.backendType}</Badge>
                    {#if probe?.error}
                        <Badge color="danger" title={probe.error}>
                            Unhealthy
                        </Badge>
                    {:else if probe}
                        <Badge color="success">Healthy</Badge>
                    {/if}
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
                    · {backend.auth.method}

                    {#if probe?.error}
                        <span class="text-danger">· {probe.error}</span>
                    {/if}
                </div>
            </div>
        {/snippet}
        {#snippet empty()}
            <EmptyState
                title="None yet"
                hint="Secret backends let you reference passwords and private keys from Vault / OpenBao"
            />
        {/snippet}
    </ItemList>
{/key}

{#if modalOpen}
    <SecretBackendModal bind:isOpen={modalOpen} instance={editing} {save} />
{/if}
