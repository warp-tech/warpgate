<script lang="ts">
    import { FormGroup, Input } from '@sveltestrap/sveltestrap'
    import { api, type CheckSshHostKeyResponseBody, type SSHKnownHost, type TargetOptionsTargetSSHOptions } from './lib/api'
    import { faCheck, faExternalLink, faWarning } from '@fortawesome/free-solid-svg-icons'
    import Fa from 'svelte-fa'
    import AsyncButton from 'common/AsyncButton.svelte'
    import Alert from 'common/sveltestrap-s5-ports/Alert.svelte'
    import CopyButton from 'common/CopyButton.svelte';

    interface Props {
        id: string,
        options: TargetOptionsTargetSSHOptions;
    }

    // svelte-ignore non_reactive_update
    enum RemoteHostKeyState {
        Valid,
        Invalid,
        Unknown
    }

    let { id, options }: Props = $props()
    let knownHosts: SSHKnownHost[] | null = $state(null)
    let remoteHostKey: CheckSshHostKeyResponseBody | null = $state(null)
    let remoteHostKeyState: RemoteHostKeyState | null = $derived.by(() => {
        if (!remoteHostKey || !knownHosts) {
            return null
        }
        if (knownHosts.some(k => k.keyType === remoteHostKey!.remoteKeyType && k.keyBase64 === remoteHostKey!.remoteKeyBase64)) {
            return RemoteHostKeyState.Valid
        } else {
            return knownHosts.length ? RemoteHostKeyState.Invalid : RemoteHostKeyState.Unknown
        }
    })

    $effect(() => {
        (async function () {
            // eslint-disable-next-line @typescript-eslint/no-unused-expressions
            options // run effect when options get reassigned after saving
            await reloadKnownHosts()
        })()
    })

    async function reloadKnownHosts () {
        knownHosts = await api.getSshTargetKnownSshHostKeys({ id })
    }

    async function checkRemoteHostKey () {
        remoteHostKey = null
        if (!options.host || !options.port) {
            return
        }
        remoteHostKey = await api.checkSshHostKey({
            checkSshHostKeyRequest: options,
        })
    }

    async function trustRemoteKey () {
        await api.addSshKnownHost({
            addSshKnownHostRequest: {
                host: options.host,
                port: options.port,
                keyBase64: remoteHostKey!.remoteKeyBase64,
                keyType: remoteHostKey!.remoteKeyType,
            }
        })
        await reloadKnownHosts()
    }
</script>

<div class="row">
    <div class="col-8">
        <FormGroup floating label="Target host">
            <input class="form-control" bind:value={options.host} />
        </FormGroup>
    </div>
    <div class="col-4">
        <FormGroup floating label="Target port">
            <input class="form-control" type="number" bind:value={options.port} min="1" max="65535" step="1" />
        </FormGroup>
    </div>
</div>

<FormGroup floating label="Username">
    <input class="form-control"
        placeholder="Use the currently logged in user's name"
        bind:value={options.username}
    />
</FormGroup>

<div class="d-flex">
    <FormGroup floating label="Authentication" class="w-100">
        <select bind:value={options.auth.kind} class="form-control">
            <option value={'PublicKey'}>Warpgate's private keys</option>
            <option value={'Password'}>Password</option>
        </select>
    </FormGroup>
    {#if options.auth.kind === 'PublicKey'}
        <a
            class="btn btn-link mb-3 d-flex align-items-center"
            href="/@warpgate/admin#/config/ssh"
            target="_blank">
            <Fa fw icon={faExternalLink} />
        </a>
    {/if}
    {#if options.auth.kind === 'Password'}
        <FormGroup floating label="Password" class="w-100 ms-3">
            <input class="form-control" type="password" autocomplete="off" bind:value={options.auth.password} />
        </FormGroup>
    {/if}
</div>

<div class="d-flex">
    <Input
        class="mb-0 me-2"
        type="switch"
        label="Allow insecure SSH algorithms (e.g. for older network devices)"
        bind:checked={options.allowInsecureAlgos} />
</div>

<h4 class="mt-4">Remote host key</h4>


<div class="d-flex host-key-status">
    {#if remoteHostKeyState === null}
        <Alert color="secondary">
            {#if knownHosts?.length}
                There is a saved trusted key
            {:else}
                Status unknown
            {/if}
        </Alert>
    {/if}
    {#if remoteHostKeyState === RemoteHostKeyState.Valid}
        <Alert color="success" class="d-flex align-items-center">
            <Fa icon={faCheck} class="me-3" />
            Remote key is trusted
        </Alert>
    {/if}
    {#if remoteHostKeyState === RemoteHostKeyState.Unknown}
        <Alert color="warning">
            <div>Remote host key is not trusted yet</div>
            <pre class="key-value">{remoteHostKey?.remoteKeyType} {remoteHostKey?.remoteKeyBase64} <CopyButton link text={remoteHostKey?.remoteKeyType + ' ' + remoteHostKey?.remoteKeyBase64} class="copy-button" /></pre>
        </Alert>
    {/if}

    {#if remoteHostKeyState === RemoteHostKeyState.Invalid}
        <Alert color="danger" class="d-flex align-items-center">
            <Fa icon={faWarning} class="me-3" />
            <div style="min-width: 0">
                <h5>Remote host key has changed!</h5>
                {#if knownHosts}
                    <strong>Known trusted keys:</strong>
                    <div class="mb-2">
                        {#each knownHosts as host}
                            <pre class="key-value">{host.keyType} {host.keyBase64} <CopyButton link text={host.keyType + ' ' + host.keyBase64} class="copy-button" /></pre>
                        {/each}
                    </div>
                {/if}
                <strong>Current remote key:</strong>
                <pre class="key-value">{remoteHostKey?.remoteKeyType} {remoteHostKey?.remoteKeyBase64} <CopyButton link text={remoteHostKey?.remoteKeyType + ' ' + remoteHostKey?.remoteKeyBase64} class="copy-button" /></pre>
            </div>
        </Alert>
    {/if}
    <div class="buttons">
        {#if remoteHostKeyState === RemoteHostKeyState.Unknown}
            <AsyncButton color="primary" click={trustRemoteKey} class="ms-3">
                Trust
            </AsyncButton>
        {/if}

        {#if remoteHostKeyState === RemoteHostKeyState.Invalid}
            <AsyncButton color="danger" click={trustRemoteKey} class="ms-3">
                Trust the new key
            </AsyncButton>
        {/if}

        <AsyncButton color="secondary" click={checkRemoteHostKey} class="ms-3">
            {#if remoteHostKeyState === null}
                Check host key
            {:else}
                Recheck
            {/if}
        </AsyncButton>
    </div>
</div>

<style lang="scss">
    .host-key-status {
        :global(.alert) {
            min-width: 0;
            flex-grow: 1;
            padding-top: 0.5rem;
            padding-bottom: 0.5rem;
            margin-bottom: 0;
        }

        .key-value {
            word-wrap: break-word;
            margin-bottom: 0;
            white-space: break-spaces;

            background: rgba(0, 0, 0, .5);
            border-radius: 3px;
            padding: 5px 10px;

            :global(.copy-button) {
                float: right;
                margin-left: 0.5rem;
            }
        }

        .buttons {
            display: flex;
            flex-direction: column;
            flex-wrap: wrap;
            align-items: stretch;
            gap: 0.5rem;
            flex-shrink: 0;

            :global(.btn) {
                flex: 1 0 auto;
            }
        }


    }
</style>
