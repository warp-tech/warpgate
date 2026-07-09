<script module lang="ts">
    import { api, type SecretReferenceUsage } from 'admin/lib/api'

    export interface SecretBackendOption {
        name: string
        backendType: 'vault' | 'openbao'
    }

    let backendsPromise: Promise<SecretBackendOption[]> | null = null

    export function loadSecretBackends (): Promise<SecretBackendOption[]> {
        if (!backendsPromise) {
            backendsPromise = api.getSecretBackends()
                .then(list =>
                    list.map(b => ({ name: b.name, backendType: b.backendType })))
                .catch(() => {
                    backendsPromise = null
                    return []
                })
        }
        return backendsPromise
    }

    let usagePromise: Promise<SecretReferenceUsage[]> | null = null

    export function loadSecretReferenceUsage (): Promise<SecretReferenceUsage[]> {
        if (!usagePromise) {
            usagePromise = api.getSecretReferenceUsage().catch(() => {
                usagePromise = null
                return []
            })
        }
        return usagePromise
    }
</script>

<script lang="ts">
    import { Button, Modal, ModalBody, ModalFooter, ModalHeader } from '@sveltestrap/sveltestrap'
    import { push } from 'svelte-spa-router'

    const REFERENCE_PREFIXES = ['vault://', 'openbao://']

    interface Props {
        value: string
        disabled?: boolean
        multiline?: boolean
        placeholder?: string
    }

    let {
        value = $bindable(''),
        disabled = false,
        multiline = false,
        placeholder = '',
    }: Props = $props()

    function isRef (v: string | undefined): boolean {
        return REFERENCE_PREFIXES.some(p => (v ?? '').startsWith(p))
    }

    interface ParsedRef { scheme: string, backend: string, path: string, key: string }

    function parseRef (v: string): ParsedRef {
        const prefix = REFERENCE_PREFIXES.find(p => v.startsWith(p))
        if (!prefix) {
            return { scheme: 'vault', backend: '', path: '', key: '' }
        }
        const scheme = prefix.slice(0, -3) // strip '://'
        const rest = v.slice(prefix.length) // backend/path#key
        const slash = rest.indexOf('/')
        const backend = slash === -1 ? rest : rest.slice(0, slash)
        const afterBackend = slash === -1 ? '' : rest.slice(slash + 1) // path#key
        const hash = afterBackend.indexOf('#')
        const path = hash === -1 ? afterBackend : afterBackend.slice(0, hash)
        const key = hash === -1 ? '' : afterBackend.slice(hash + 1)
        return { scheme, backend, path, key }
    }

    function composeRef (p: ParsedRef): string {
        const base = `${p.scheme}://${p.backend}/${p.path}`
        return p.key ? `${base}#${p.key}` : base
    }

    const initial = parseRef(value)
    let refScheme = $state(initial.scheme)
    let refBackend = $state(initial.backend)
    let refPath = $state(initial.path)
    let refKey = $state(initial.key)

    let mode = $state<'inline' | 'reference'>(isRef(value) ? 'reference' : 'inline')

    let lastComposed = $state(isRef(value) ? value : '')

    $effect(() => {
        if (value === lastComposed) {
            return
        }
        if (isRef(value)) {
            const p = parseRef(value)
            refScheme = p.scheme
            refBackend = p.backend
            refPath = p.path
            refKey = p.key
            lastComposed = value
            mode = 'reference'
        } else {
            mode = 'inline'
        }
    })

    let backends = $state<SecretBackendOption[]>([])
    let backendsLoaded = $state(false)

    loadSecretBackends().then(list => {
        backends = list
        backendsLoaded = true
        if (mode === 'reference' && !refBackend && list.length) {
            selectBackend(list[0]!.name)
        }
    })

    let backendOptions = $derived.by<SecretBackendOption[]>(() => {
        if (refBackend && !backends.some(b => b.name === refBackend)) {
            return [{ name: refBackend, backendType: refScheme === 'openbao' ? 'openbao' : 'vault' }, ...backends]
        }
        return backends
    })

    function recompose () {
        const composed = composeRef({ scheme: refScheme, backend: refBackend, path: refPath, key: refKey })
        value = composed
        lastComposed = composed
        testResult = null
        testError = undefined
    }

    function selectBackend (name: string) {
        refBackend = name
        const chosen = backends.find(b => b.name === name)
        if (chosen) {
            refScheme = chosen.backendType === 'openbao' ? 'openbao' : 'vault'
        }
        recompose()
    }

    let referenceUsage = $state<SecretReferenceUsage[]>([])
    loadSecretReferenceUsage().then(list => { referenceUsage = list })

    let currentUsage = $derived.by<SecretReferenceUsage | null>(() => {
        if (mode !== 'reference' || !refBackend || !refPath) {
            return null
        }
        const composed = composeRef({ scheme: refScheme, backend: refBackend, path: refPath, key: refKey })
        return referenceUsage.find(u => u.reference === composed) ?? null
    })

    let usageModalOpen = $state(false)

    let pendingNavigateTargetId: string | null = null

    function clickTargetLink (e: MouseEvent, id: string) {
        if (e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) {
            return
        }
        e.preventDefault()
        pendingNavigateTargetId = id
        usageModalOpen = false
    }

    function onUsageModalClosed () {
        if (pendingNavigateTargetId) {
            push(`/config/targets/${pendingNavigateTargetId}`)
            pendingNavigateTargetId = null
        }
    }

    let testing = $state(false)
    let testResult = $state<'ok' | 'error' | null>(null)
    let testError = $state<string | undefined>()

    let canTest = $derived(Boolean(refBackend && refPath && refKey))

    async function testResolution () {
        if (!canTest) {
            return
        }
        testing = true
        testResult = null
        testError = undefined
        try {
            const reference = composeRef({ scheme: refScheme, backend: refBackend, path: refPath, key: refKey })
            const data = await api.testSecretResolve({ testResolveRequest: { reference } })
            testResult = data.ok ? 'ok' : 'error'
            testError = data.error ?? undefined
        } catch (e) {
            testResult = 'error'
            testError = String(e)
        } finally {
            testing = false
        }
    }
</script>

{#if mode === 'inline'}
    {#if multiline}
        <textarea
            class="form-control font-monospace"
            rows="8"
            bind:value
            {disabled}
            {placeholder}
        ></textarea>
    {:else}
        <input
            class="form-control"
            type="password"
            autocomplete="off"
            bind:value
            {disabled}
        />
    {/if}

{:else}
    <div class="border rounded p-3">
        <div class="d-flex align-items-center gap-2 mb-2 text-muted small">
            <span>This credential is read from a secret backend at connection time — the value is never stored here.</span>
        </div>

        {#if currentUsage && currentUsage.targetCount > 1}
            <div class="mb-2">
                <button
                    type="button"
                    class="btn btn-link p-0 border-0 align-baseline"
                    onclick={() => { usageModalOpen = true }}
                >
                    <span
                        class="badge bg-info-subtle text-info-emphasis text-decoration-underline"
                        title="Click to see which targets share this secret"
                    >
                        Used by {currentUsage.targetCount} targets
                    </span>
                </button>
            </div>

            <Modal
                isOpen={usageModalOpen}
                toggle={() => { usageModalOpen = false }}
                on:close={onUsageModalClosed}
            >
                <ModalHeader>
                    Targets sharing this secret
                </ModalHeader>
                <ModalBody>
                    <p class="text-muted small">
                        The reference <code>{currentUsage.reference}</code> is used by these targets:
                    </p>
                    <ul class="list-group">
                        {#each currentUsage.targets as t (t.id)}
                            <li class="list-group-item">
                                <a href="/config/targets/{t.id}" onclick={(e) => clickTargetLink(e, t.id)}>{t.name}</a>
                            </li>
                        {/each}
                    </ul>
                </ModalBody>
                <ModalFooter>
                    <Button
                        color="secondary"
                        on:click={() => { usageModalOpen = false }}
                    >
                        Close
                    </Button>
                </ModalFooter>
            </Modal>
        {/if}

        <div class="mb-2">
            <label class="form-label mb-1 small fw-semibold" for="sri-backend">Secret backend</label>
            <select
                id="sri-backend"
                class="form-select"
                value={refBackend}
                {disabled}
                onchange={(e) => selectBackend((e.target as HTMLSelectElement).value)}
            >
                {#if !refBackend}
                    <option value="" disabled selected>Select a backend…</option>
                {/if}
                {#each backendOptions as b (b.name)}
                    <option value={b.name}>{b.name} ({b.backendType})</option>
                {/each}
            </select>
            {#if backendsLoaded && backends.length === 0}
                <div class="form-text text-warning">
                    No secret backends are configured. Add one under <code>secrets:</code> in
                    <code>warpgate.yaml</code>, or
                    <a href="/@warpgate/admin#/config/secret-backends">view backends</a>.
                </div>
            {/if}
        </div>

        <div class="mb-2">
            <label class="form-label mb-1 small fw-semibold" for="sri-path">Secret path</label>
            <input
                id="sri-path"
                class="form-control font-monospace"
                type="text"
                value={refPath}
                {disabled}
                placeholder="secret/myapp"
                oninput={(e) => { refPath = (e.target as HTMLInputElement).value; recompose() }}
            />
            <div class="form-text">
                The KV mount and secret name, exactly as in Vault — <strong>without</strong> the
                <code>data/</code> prefix. E.g. <code>vault kv get secret/myapp</code> → <code>secret/myapp</code>.
            </div>
        </div>

        <div class="mb-2">
            <label class="form-label mb-1 small fw-semibold" for="sri-key">Key (field inside the secret)</label>
            <input
                id="sri-key"
                class="form-control font-monospace"
                type="text"
                value={refKey}
                {disabled}
                placeholder="password"
                oninput={(e) => { refKey = (e.target as HTMLInputElement).value; recompose() }}
            />
            <div class="form-text">
                Which key of the secret to read, e.g. <code>password</code> from
                <code>{`{ "password": "…", "username": "…" }`}</code>.
            </div>
        </div>

        <div class="d-flex align-items-center gap-2 flex-wrap mt-2">
            <button
                type="button"
                class="btn btn-secondary"
                disabled={!canTest || testing || disabled}
                onclick={testResolution}
                title={canTest
                    ? 'Test whether this secret can be retrieved from the backend right now'
                    : 'Select a backend and enter both a path and a key to test'}
            >
                {#if testing}
                    <span class="spinner-border spinner-border-sm" role="status"></span>
                    Testing…
                {:else}
                    Test retrieval
                {/if}
            </button>

            {#if testResult === 'ok'}
                <span class="text-success small">✓ Secret retrieved successfully</span>
            {:else if testResult === 'error'}
                <span class="text-danger small" title={testError}>✗ {testError ?? 'Retrieval failed'}</span>
            {/if}
        </div>
    </div>
{/if}
