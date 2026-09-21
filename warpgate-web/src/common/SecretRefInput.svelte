<script module lang="ts">
    import { api, type SecretReferenceUsage } from 'admin/lib/api'

    export interface SecretBackendOption {
        name: string
        backendType: 'vault' | 'openbao'
    }

    let backendsPromise: Promise<SecretBackendOption[]> | null = null

    export function invalidateSecretBackends(): void {
        backendsPromise = null
    }

    export function loadSecretBackends(): Promise<SecretBackendOption[]> {
        if (!backendsPromise) {
            backendsPromise = api
                .getSecretBackendsSummary()
                .then(list =>
                    list.map(b => ({
                        name: b.name,
                        backendType: b.backendType,
                    })),
                )
                .catch(() => {
                    backendsPromise = null
                    return []
                })
        }
        return backendsPromise
    }

    let usagePromise: Promise<SecretReferenceUsage[]> | null = null

    export function loadSecretReferenceUsage(): Promise<
        SecretReferenceUsage[]
    > {
        if (!usagePromise) {
            usagePromise = api.getSecretReferenceUsage().catch(() => {
                usagePromise = null
                return []
            })
        }
        return usagePromise
    }

    const REFERENCE_SCHEME = 'secret://'

    export function isSecretRef(v: string | undefined): boolean {
        return (v ?? '').startsWith(REFERENCE_SCHEME)
    }

    interface ParsedRef {
        backend: string
        path: string
        key: string
    }

    function parseSecretRef(v: string): ParsedRef {
        if (!isSecretRef(v)) {
            return { backend: '', path: '', key: '' }
        }
        const rest = v.slice(REFERENCE_SCHEME.length)
        const slash = rest.indexOf('/')
        const backend = slash === -1 ? rest : rest.slice(0, slash)
        const afterBackend = slash === -1 ? '' : rest.slice(slash + 1)
        const hash = afterBackend.indexOf('#')
        const path = hash === -1 ? afterBackend : afterBackend.slice(0, hash)
        const key = hash === -1 ? '' : afterBackend.slice(hash + 1)
        return { backend, path, key }
    }

    function composeSecretRef(p: ParsedRef): string {
        const base = `${REFERENCE_SCHEME}${p.backend}/${p.path}`
        return p.key ? `${base}#${p.key}` : base
    }
</script>

<script lang="ts">
    import { faKey } from '@fortawesome/free-solid-svg-icons'
    import {
        Button,
        FormGroup,
        Modal,
        ModalBody,
        ModalFooter,
        ModalHeader,
    } from '@sveltestrap/sveltestrap'
    import { stringifyError } from 'common/errors'
    import Fa from 'svelte-fa'

    interface Props {
        value: string
        disabled?: boolean
        // Whether the reference names one field of the secret (`#key`)
        withKey?: boolean
        // When set, the value may also be entered directly, under this label
        inlineLabel?: string
    }

    let {
        value = $bindable(''),
        disabled = false,
        withKey = true,
        inlineLabel,
    }: Props = $props()

    // svelte-ignore state_referenced_locally
    let refMode = $state(!inlineLabel || isSecretRef(value))
    // A reference set from outside (e.g. the loaded target) switches to
    // reference mode; clearing the value on a mode switch does not switch back.
    $effect(() => {
        if (isSecretRef(value)) {
            refMode = true
        }
    })

    function switchMode(toRef: boolean) {
        refMode = toRef
        value = ''
    }

    let current = $derived(parseSecretRef(value))
    let chosen = $derived(
        isSecretRef(value) && Boolean(current.backend && current.path),
    )
    let label = $derived(
        chosen
            ? `${current.backend}: ${current.path}${current.key ? `#${current.key}` : ''}`
            : 'Choose secret…',
    )

    let modalOpen = $state(false)
    let backends = $state<SecretBackendOption[]>([])
    let backendsLoaded = $state(false)
    let usage = $state<SecretReferenceUsage[]>([])

    // The draft only becomes `value` on Save.
    let draftBackend = $state('')
    let draftPath = $state('')
    let draftKey = $state('')

    let draft = $derived(
        composeSecretRef({
            backend: draftBackend,
            path: draftPath,
            key: draftKey,
        }),
    )
    let complete = $derived(
        Boolean(draftBackend && draftPath && (draftKey || !withKey)),
    )
    let sharedWith = $derived(
        usage.find(u => u.reference === draft)?.targets ?? [],
    )

    let testing = $state(false)
    let testResult = $state<{ ok: boolean; error?: string } | null>(null)
    let testSequence = 0

    // Retrieval is checked as the draft changes, after a short pause in typing;
    // a reply for an older draft is dropped.
    $effect(() => {
        const reference = draft
        if (!modalOpen || !complete) {
            testResult = null
            testing = false
            return
        }
        const sequence = ++testSequence
        testResult = null
        const timer = setTimeout(async () => {
            testing = true
            let result: { ok: boolean; error?: string }
            try {
                await api.testSecretResolve({
                    testResolveRequest: { reference },
                })
                result = { ok: true }
            } catch (e) {
                result = { ok: false, error: await stringifyError(e) }
            }
            if (sequence === testSequence) {
                testResult = result
                testing = false
            }
        }, 500)
        return () => clearTimeout(timer)
    })

    function open() {
        draftBackend = current.backend
        draftPath = current.path
        draftKey = current.key
        modalOpen = true
        loadSecretBackends().then(list => {
            backends = list
            backendsLoaded = true
            if (!draftBackend && list.length) {
                draftBackend = list[0]!.name
            }
        })
        loadSecretReferenceUsage().then(list => {
            usage = list
        })
    }

    function save() {
        value = draft
        modalOpen = false
    }
</script>

{#if refMode}
    <div class="d-flex align-items-center gap-3 mb-3">
        <Button
            color="secondary"
            class="secret-ref-button d-flex align-items-center gap-2"
            {disabled}
            onclick={open}
        >
            <Fa icon={faKey} />
            {label}
        </Button>
        {#if inlineLabel}
            <Button
                color="link"
                class="px-0 text-nowrap"
                {disabled}
                onclick={() => switchMode(false)}
            >
                Enter directly
            </Button>
        {/if}
    </div>
{:else}
    <div class="d-flex align-items-center gap-3">
        <FormGroup floating label={inlineLabel ?? ''} class="flex-grow-1">
            <input
                class="form-control"
                type="password"
                autocomplete="off"
                {disabled}
                bind:value
            >
        </FormGroup>
        <Button
            color="link"
            class="px-0 mb-3 text-nowrap"
            {disabled}
            onclick={() => switchMode(true)}
        >
            Use secret backend
        </Button>
    </div>
{/if}

<Modal isOpen={modalOpen} toggle={() => (modalOpen = false)}>
    <ModalHeader>Secret</ModalHeader>
    <ModalBody>
        <FormGroup floating label="Backend">
            <select class="form-select" bind:value={draftBackend}>
                {#each backends as b (b.name)}
                    <option value={b.name}>{b.name} ({b.backendType})</option>
                {/each}
            </select>
            {#if backendsLoaded && !backends.length}
                <div class="form-text text-warning">
                    No secret backends. Add one under
                    <a href="/@warpgate/admin#/config/secret-backends">
                        Config → Secret backends
                    </a>.
                </div>
            {/if}
        </FormGroup>
        <FormGroup
            floating
            label="Path (mount/path, KV v2, without the data/ segment)"
        >
            <input
                class="form-control font-monospace"
                placeholder="secret/myapp"
                bind:value={draftPath}
            >
        </FormGroup>
        {#if withKey}
            <FormGroup floating label="Field">
                <input
                    class="form-control font-monospace"
                    placeholder="password"
                    bind:value={draftKey}
                >
            </FormGroup>
        {/if}
        {#if sharedWith.length}
            <div class="form-text">
                Also used by
                {#each sharedWith as t, i (t.id)}
                    {i ? ', ' : ''}
                    <a href="#/config/targets/{t.id}">{t.name}</a>
                {/each}
            </div>
        {/if}
        {#if testing}
            <div class="text-muted small">Checking…</div>
        {:else if testResult}
            <div
                class={testResult.ok ? 'text-success small' : 'text-danger small'}
            >
                {testResult.ok ? 'Secret is available' : testResult.error}
            </div>
        {/if}
    </ModalBody>
    <ModalFooter>
        <Button
            color="primary"
            class="modal-button"
            disabled={!complete}
            onclick={save}
        >
            Save
        </Button>
        <Button
            color="danger"
            class="modal-button"
            onclick={() => (modalOpen = false)}
        >
            Cancel
        </Button>
    </ModalFooter>
</Modal>

<style lang="scss">
    :global(.secret-ref-button) {
        display: flex;
        text-align: left;
        min-width: 0;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
    }
</style>
