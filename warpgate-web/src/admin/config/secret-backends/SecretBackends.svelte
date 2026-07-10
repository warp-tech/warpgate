<script lang="ts">
    import { api, type SecretBackendStatus, type CheckHealthResponse } from 'admin/lib/api'

    let backends = $state<SecretBackendStatus[]>([])
    let loading = $state(true)
    let loadError = $state<string | undefined>()
    let checkingHealth = $state<Record<string, boolean>>({})

    async function load() {
        loading = true
        loadError = undefined
        try {
            backends = await api.getSecretBackends()
        } catch (e) {
            loadError = String(e)
        } finally {
            loading = false
        }
    }

    async function checkHealth(name: string) {
        checkingHealth = { ...checkingHealth, [name]: true }
        try {
            const result: CheckHealthResponse = await api.checkSecretBackendHealth({ name })
            backends = backends.map(b =>
                b.name === name
                    ? { ...b, health: result.health, healthError: result.error }
                    : b,
            )
        } catch (e) {
            backends = backends.map(b =>
                b.name === name
                    ? { ...b, health: 'error', healthError: String(e) }
                    : b,
            )
        } finally {
            checkingHealth = { ...checkingHealth, [name]: false }
        }
    }

    $effect(() => { load() })
</script>

<div class="container-max-md">
    <div class="page-header mb-3">
        <h3>Secret Backends</h3>
    </div>

    <p class="text-muted mb-4">
        Secret backends let targets pull secrets from HashiCorp Vault or OpenBao at connection
        time, instead of storing passwords inline. On any credential field, switch to
        reference mode and pick a backend, then fill in the secret path and the key (the field
        inside the secret) — Warpgate composes these into a <code>vault://</code> /
        <code>openbao://</code> reference for you. The path is the Vault CLI path
        <em>without</em> the <code>data/</code> prefix — e.g. <code>vault kv get secret/myapp</code>
        maps to path <code>secret/myapp</code>.
        <br />
        Backends are declared under <code>secrets:</code> in <code>warpgate.yaml</code>.
        Warpgate watches that file and picks up changes automatically — no restart needed.
        They cannot be managed from this UI.
    </p>

    {#if loading}
        <p class="text-muted">Loading…</p>
    {:else if loadError}
        <div class="alert alert-danger">{loadError}</div>
    {:else if backends.length === 0}
        <div class="alert alert-secondary">
            No secret backends are configured.
            Add a <code>secrets:</code> section to <code>warpgate.yaml</code> to enable
            Vault / OpenBao integration.
        </div>
    {:else}
        {#each backends as backend (backend.name)}
            {@const isChecking = checkingHealth[backend.name] ?? false}
            <div class="card mb-3">
                <div class="card-body">
                    <div class="d-flex align-items-start justify-content-between flex-wrap gap-2">
                        <div>
                            <h5 class="card-title mb-1">
                                {backend.name}
                            </h5>
                            <div class="text-muted small">
                                <span class="badge bg-secondary text-uppercase me-2">
                                    {backend.backendType}
                                </span>
                                {backend.address}
                                {#if backend.namespace}
                                    &nbsp;·&nbsp; namespace:&nbsp;<code>{backend.namespace}</code>
                                {/if}
                            </div>
                        </div>

                        <div class="d-flex align-items-center gap-2">
                            {#if backend.health === 'ok'}
                                <span class="badge bg-success">Healthy</span>
                            {:else if backend.health === 'error'}
                                <span class="badge bg-danger" title={backend.healthError ?? ''}>
                                    Unhealthy
                                </span>
                            {:else}
                                <span class="badge bg-secondary">○ Unknown</span>
                            {/if}

                            <button
                                type="button"
                                class="btn btn-outline-secondary btn-sm"
                                disabled={isChecking}
                                onclick={() => checkHealth(backend.name)}
                            >
                                {isChecking ? 'Checking…' : 'Check health'}
                            </button>
                        </div>
                    </div>

                    {#if backend.health === 'error' && backend.healthError}
                        <div class="alert alert-danger alert-sm mb-0 mt-2 py-1 px-2 small">
                            {backend.healthError}
                        </div>
                    {/if}
                </div>
            </div>
        {/each}
    {/if}
</div>
