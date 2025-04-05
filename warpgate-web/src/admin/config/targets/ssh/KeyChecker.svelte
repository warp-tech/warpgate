<script lang="ts">
    import { api, type CheckSshHostKeyResponseBody, type SSHKnownHost, type TargetOptionsTargetSSHOptions } from '../../../lib/api'
    import AsyncButton from 'common/AsyncButton.svelte'
    import Alert from 'common/sveltestrap-s5-ports/Alert.svelte'
    import KeyCheckerResult, { Key, type CheckResult } from './KeyCheckerResult.svelte'

    type State = {
        state: 'initializing'
    } | {
        state: 'not-checked',
        hasTrustedKeys: boolean
    } | {
        state: 'checking',
        previousResult: CheckResult | null
    } | {
        state: 'ready',
        result: CheckResult
    }

    let _state: State = $state({
        state: 'initializing',
    })

    interface Props {
        id: string,
        options: TargetOptionsTargetSSHOptions;
    }

    let { id, options }: Props = $props()
    let knownHosts: SSHKnownHost[] | null = $state(null)
    let remoteHostKey: CheckSshHostKeyResponseBody | null = $state(null)

    $effect(() => {
        (async function () {
            // eslint-disable-next-line @typescript-eslint/no-unused-expressions
            options // run effect when options get reassigned after saving, since changes in host/ip invalidate the currenty loaded known hosts
            _state = { state: 'initializing' }
            await reloadKnownHosts()
            updateReadyState()
        })()
    })

    function updateReadyState () {
        if (!remoteHostKey) {
            if (knownHosts === null) {
                _state = { state: 'initializing' }
                return
            } else {
                _state = { state: 'not-checked', hasTrustedKeys: knownHosts.length > 0 }
                return
            }
        }

        _state = { state: 'ready', result: getCheckResult(knownHosts, remoteHostKey) }
    }

    function getCheckResult (knownHosts: SSHKnownHost[] | null, remoteHostKey: CheckSshHostKeyResponseBody): CheckResult {
        const actualKey = new Key(remoteHostKey.remoteKeyType, remoteHostKey.remoteKeyBase64)

        if (knownHosts?.some(k => k.keyType === remoteHostKey!.remoteKeyType && k.keyBase64 === remoteHostKey!.remoteKeyBase64)) {
            return  {
                state: 'key-valid',
            }
        } else {
            return knownHosts?.length ? {
                state: 'key-invalid',
                actualKey,
                trustedKeys: knownHosts.map(k => new Key(k.keyType, k.keyBase64)),
            } : {
                state: 'key-unknown',
                actualKey,
            }
        }
    }

    async function reloadKnownHosts () {
        knownHosts = await api.getSshTargetKnownSshHostKeys({ id })
    }

    async function checkRemoteHostKey () {
        if (!options.host || !options.port) {
            return
        }
        _state = { state: 'checking', previousResult: _state.state === 'ready' ? _state.result : null }
        remoteHostKey = await api.checkSshHostKey({
            checkSshHostKeyRequest: options,
        })
        updateReadyState()
    }

    async function trustRemoteKey () {
        await api.addSshKnownHost({
            addSshKnownHostRequest: {
                host: options.host,
                port: options.port,
                keyBase64: remoteHostKey!.remoteKeyBase64,
                keyType: remoteHostKey!.remoteKeyType,
            },
        })
        await reloadKnownHosts()
        updateReadyState()
    }
</script>

<div class="d-flex host-key-status">
    {#if _state.state === 'initializing'}
    <Alert color="secondary">
        Looking for trusted keys...
    </Alert>
    {/if}

    {#if _state.state === 'not-checked'}
    <Alert color="secondary">
        {#if _state.hasTrustedKeys}
            There is a saved trusted key
        {:else}
            There are no trusted host keys yet
        {/if}
    </Alert>
    {/if}

    {#if _state.state === 'checking'}
        {#if _state.previousResult}
            <KeyCheckerResult result={_state.previousResult} />
        {:else}
            <Alert color="secondary">
                Retrieving remote host key...
            </Alert>
        {/if}
    {/if}

    {#if _state.state === 'ready'}
        <KeyCheckerResult result={_state.result} />
    {/if}

    <div class="buttons">
        {#if _state.state === 'ready' && _state.result.state === 'key-unknown'}
            <AsyncButton color="primary" click={trustRemoteKey}>
                Trust
            </AsyncButton>
        {/if}

        {#if _state.state === 'ready' && _state.result.state === 'key-invalid'}
            <AsyncButton color="danger" click={trustRemoteKey}>
                Trust the new key
            </AsyncButton>
        {/if}

        <AsyncButton color="secondary" click={checkRemoteHostKey}>
            {#if _state.state === 'ready' || _state.state === 'checking' && _state.previousResult}
                Recheck
            {:else}
                Check host key
            {/if}
        </AsyncButton>
    </div>
</div>

<style lang="scss">
    .host-key-status {
        .buttons {
            display: flex;
            flex-direction: column;
            flex-wrap: wrap;
            align-items: stretch;
            gap: 0.5rem;
            flex-shrink: 0;
            margin-left: 0.5rem;

            :global(.btn) {
                flex: 1 0 auto;
            }
        }
    }

    :global(.alert) {
        min-width: 0;
        flex-grow: 1;
        padding-top: 0.5rem;
        padding-bottom: 0.5rem;
        margin-bottom: 0;
    }
</style>
