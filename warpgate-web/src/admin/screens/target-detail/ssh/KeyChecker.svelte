<script lang="ts">
    /**
     * SSH host-key trust state.
     *
     * The state machine is preserved verbatim from
     * config/targets/ssh/KeyChecker.svelte — including the effect that resets
     * to `initializing` whenever `options` is reassigned, because a changed
     * host or port invalidates the known hosts already loaded.
     *
     * Two changes, both deliberate:
     *
     * 1. Trusting a CHANGED key is a destructive button behind a typed
     *    confirmation. It was a quiet secondary button next to a warning.
     *    Accepting a changed host key is accepting a possible
     *    machine-in-the-middle, and it is not taken under time pressure the
     *    way terminating a session is — it follows a deliberate rekey. Typing
     *    the hostname forces the operator to read which host they are
     *    trusting. Trusting a FIRST key stays a plain primary action: there is
     *    no prior key, so there is nothing to contradict.
     *
     * 2. Messages move from sveltestrap Alert to Callout.
     */
    import {
        api,
        type CheckSshHostKeyResponseBody,
        type SSHKnownHost,
        type TargetOptionsTargetSSHOptions,
    } from 'admin/lib/api'
    import { stringifyError } from 'common/errors'
    import Button from 'ui/Button.svelte'
    import Callout from 'ui/Callout.svelte'
    import ConfirmDialog from 'ui/ConfirmDialog.svelte'
    import KeyCheckerResult, {
        type CheckResult,
        Key,
    } from './KeyCheckerResult.svelte'

    type State =
        | { state: 'initializing' }
        | { state: 'not-checked'; hasTrustedKeys: boolean }
        | { state: 'checking'; previousResult: CheckResult | null }
        | { state: 'ready'; result: CheckResult }
        | { state: 'error'; error: string }

    let _state: State = $state({ state: 'initializing' })

    interface Props {
        id: string
        options: TargetOptionsTargetSSHOptions
    }

    let { id, options }: Props = $props()
    let knownHosts: SSHKnownHost[] | null = $state(null)
    let remoteHostKey: CheckSshHostKeyResponseBody | null = $state(null)
    let confirmTrustChangedOpen = $state(false)

    $effect(() => {
        ;(async () => {
            // Re-runs when options are reassigned after saving: a changed host
            // or port invalidates the currently loaded known hosts.
            options
            _state = { state: 'initializing' }
            await reloadKnownHosts()
            updateReadyState()
        })()
    })

    function updateReadyState() {
        if (!remoteHostKey) {
            if (knownHosts === null) {
                _state = { state: 'initializing' }
                return
            }
            _state = {
                state: 'not-checked',
                hasTrustedKeys: knownHosts.length > 0,
            }
            return
        }

        _state = {
            state: 'ready',
            result: getCheckResult(knownHosts, remoteHostKey),
        }
    }

    function getCheckResult(
        hosts: SSHKnownHost[] | null,
        remote: CheckSshHostKeyResponseBody,
    ): CheckResult {
        if (!remote) {
            throw new Error('Remote host key not loaded')
        }

        const actualKey = new Key(remote.remoteKeyType, remote.remoteKeyBase64)

        if (
            hosts?.some(
                k =>
                    k.keyType === remote.remoteKeyType &&
                    k.keyBase64 === remote.remoteKeyBase64,
            )
        ) {
            return { state: 'key-valid' }
        }
        return hosts?.length
            ? {
                  state: 'key-invalid',
                  actualKey,
                  trustedKeys: hosts.map(k => new Key(k.keyType, k.keyBase64)),
              }
            : { state: 'key-unknown', actualKey }
    }

    async function reloadKnownHosts() {
        try {
            knownHosts = await api.getSshTargetKnownSshHostKeys({ id })
        } catch (err) {
            _state = { state: 'error', error: await stringifyError(err) }
            throw err
        }
    }

    async function checkRemoteHostKey() {
        _state = {
            state: 'checking',
            previousResult: _state.state === 'ready' ? _state.result : null,
        }
        try {
            remoteHostKey = await api.checkSshHostKey({
                checkSshHostKeyRequest: { targetId: id },
            })
        } catch (err) {
            _state = { state: 'error', error: await stringifyError(err) }
            return
        }
        updateReadyState()
    }

    async function trustRemoteKey() {
        if (!remoteHostKey) {
            return
        }
        try {
            await api.addSshKnownHost({
                addSshKnownHostRequest: {
                    host: options.host,
                    port: options.port,
                    keyBase64: remoteHostKey.remoteKeyBase64,
                    keyType: remoteHostKey.remoteKeyType,
                },
            })
        } catch (err) {
            _state = { state: 'error', error: await stringifyError(err) }
            throw err
        }
        await reloadKnownHosts()
        updateReadyState()
    }

    // Bound to a local first: narrowing a $state union inside a $derived
    // expression collapses it to the initial variant.
    const checkLabel = $derived.by(() => {
        const s = _state
        const rechecking =
            s.state === 'ready' ||
            (s.state === 'checking' && s.previousResult !== null)
        return rechecking ? 'Recheck' : 'Check host key'
    })
</script>

{#if _state.state === 'initializing'}
    <Callout title="Looking for trusted keys…">
        {#snippet actions()}
            <Button size="compact" click={checkRemoteHostKey}>
                {checkLabel}
            </Button>
        {/snippet}
    </Callout>
{:else if _state.state === 'not-checked'}
    <Callout
        title={_state.hasTrustedKeys
            ? 'There is a saved trusted key'
            : 'There are no trusted host keys yet'}
    >
        {#snippet actions()}
            <Button size="compact" click={checkRemoteHostKey}>
                {checkLabel}
            </Button>
        {/snippet}
    </Callout>
{:else if _state.state === 'checking' && !_state.previousResult}
    <Callout title="Retrieving remote host key…" />
{:else if _state.state === 'error'}
    <Callout tone="danger" title="Host key check failed">
        {_state.error}
        {#snippet actions()}
            <Button size="compact" click={checkRemoteHostKey}>Retry</Button>
        {/snippet}
    </Callout>
{:else}
    {@const result =
        _state.state === 'ready' ? _state.result : _state.previousResult}
    {#if result}
        <div class="checker">
            <div class="checker-result">
                <KeyCheckerResult {result} />
            </div>
            <div class="checker-actions">
                {#if result.state === 'key-unknown'}
                    <Button
                        variant="primary"
                        size="compact"
                        click={trustRemoteKey}
                    >
                        Trust
                    </Button>
                {/if}
                {#if result.state === 'key-invalid'}
                    <Button
                        variant="destructive"
                        size="compact"
                        onclick={() => (confirmTrustChangedOpen = true)}
                    >
                        Trust the new key
                    </Button>
                {/if}
                <Button size="compact" click={checkRemoteHostKey}>
                    {checkLabel}
                </Button>
            </div>
        </div>
    {/if}
{/if}

<ConfirmDialog
    bind:open={confirmTrustChangedOpen}
    title="Trust the new host key for {options.host}?"
    confirmLabel="Trust the new key"
    confirmText={options.host}
    confirmTextLabel="hostname"
    onconfirm={trustRemoteKey}
>
    <p>
        Warpgate already trusts a different key for this host. Trusting the new
        one means every future connection accepts it.
    </p>
    <p>
        If this host was not deliberately rebuilt or rekeyed, the connection may
        be being intercepted. Verify the new key through a channel other than
        this one before continuing.
    </p>
</ConfirmDialog>

<style>
    .checker {
        display: flex;
        align-items: flex-start;
        gap: var(--wg-space-sm);
    }

    .checker-result {
        flex: 1 1 auto;
        min-width: 0;
    }

    .checker-actions {
        display: flex;
        flex-direction: column;
        align-items: stretch;
        gap: var(--wg-space-sm);
        flex: none;
    }

    @media (max-width: 560px) {
        .checker {
            flex-direction: column;
        }

        .checker-actions {
            flex-direction: row;
            width: 100%;
        }
    }
</style>
