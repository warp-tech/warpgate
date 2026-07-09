<script lang="ts">
    import { faWarning } from '@fortawesome/free-solid-svg-icons'
    import { Alert, Badge, Button } from '@sveltestrap/sveltestrap'
    import {
        api,
        type IpEchoInfo,
        ListenerState,
        type ListenerStatus,
    } from 'admin/lib/api'
    import HelpText from 'admin/lib/HelpText.svelte'
    import DelayedSpinner from 'common/DelayedSpinner.svelte'
    import { stringifyError } from 'common/errors'
    import Loadable from 'common/Loadable.svelte'
    import Fa from 'svelte-fa'
    import RelativeDate from '../RelativeDate.svelte'

    let loading = $state(true)
    let error: string | undefined = $state()
    let listeners: ListenerStatus[] | undefined = $state()

    const stateBadges: Record<ListenerState, string> = {
        [ListenerState.Listening]: 'success',
        [ListenerState.Disabled]: 'secondary',
        [ListenerState.BindFailed]: 'danger',
    }

    async function load() {
        loading = true
        error = undefined
        try {
            const [listenersRes] = await Promise.all([
                api.getListenerStates(),
            ])
            listeners = listenersRes
        } catch (err) {
            error = await stringifyError(err)
        } finally {
            loading = false
        }
    }

    load()
</script>

<div class="container-max-md">
    <div class="page-summary-bar">
        <h1>network status</h1>
    </div>

    {#if error}
        <Alert color="danger" dismissible onclose={() => { error = undefined }}>
            {error}
            <Button color="link" size="sm" onclick={load}>Retry</Button>
        </Alert>
    {/if}

    {#if loading && !listeners}
        <DelayedSpinner />
    {:else}
        {#if listeners}
            <h5 class="mb-2">Protocol listeners</h5>
            <div class="list-group list-group-flush mb-4">
                {#each listeners as listener (listener.name)}
                    <div class="list-group-item">
                        <div class="d-flex align-items-center gap-3">
                            <Badge color={stateBadges[listener.state]}>
                                {listener.state}
                            </Badge>
                            <div class="flex-grow-1">
                                <div class="d-flex align-items-center gap-2">
                                    <strong>{listener.name}</strong>
                                    <code class="ms-auto text-muted">
                                        {listener.address}
                                    </code>
                                </div>
                                {#if listener.error}
                                    <Alert color="danger">
                                        {listener.error}
                                    </Alert>
                                {/if}
                                {#each listener.certificates as cert, index}
                                    <small class="d-block text-muted">
                                        {(listener.certificates.length > 1)
                                    ? (index === 0 ? 'Default certificate' : 'SNI certificate')
                                    : 'Certificate'}:
                                        {cert.domains.join(', ')}
                                        {#if cert.expiry}
                                            &middot;
                                            <span
                                                class:text-danger={cert.expiry < new Date()}
                                            >
                                                expires
                                                <RelativeDate
                                                    date={cert.expiry}
                                                />
                                            </span>
                                        {/if}
                                    </small>
                                {/each}
                            </div>
                        </div>
                    </div>
                {/each}
            </div>
        {/if}

        <h5 class="mb-2">Client IP detection</h5>
        <p>
            Shows exactly how this client's IPs is being detected by Warpgate.
        </p>
        <HelpText>
            Your setup must ensure that Warpgate can see the actual client's IP
            address instead of the IP of a reverse proxy or a load balancer.
            This ensures that both audit and login protection will work
            correctly.
        </HelpText>
        <Loadable promise={api.getIpEcho()}>
            {#snippet children(ipEcho)}
                <div class="list-group list-group-flush mb-3">
                    <div class="list-group-item d-flex">
                        <span>Peer IP as seen by the server</span>
                        <span class="ms-auto">
                            {#if !ipEcho.peerIp}
                                <span
                                    class="d-flex gap-2 align-items-center text-warning"
                                >
                                    <Fa icon={faWarning} />
                                    unknown
                                </span>
                            {:else}
                                <code>
                                    {ipEcho.peerIp}
                                </code>
                            {/if}
                        </span>
                    </div>
                    <div class="list-group-item d-flex">
                        <span>X-Forwarded-For header value</span>
                        {#if !ipEcho.xForwardedFor}
                            <span class="ms-auto text-muted">not present</span>
                        {:else}
                            <code class="ms-auto">
                                {ipEcho.xForwardedFor}
                            </code>
                        {/if}
                    </div>
                    <div class="list-group-item d-flex">
                        <span>Trust X-Forwarded-* headers</span>
                        <span class="ms-auto">
                            {#if !ipEcho.trustXForwardedHeaders && ipEcho.xForwardedFor}
                                <span
                                    class="d-flex gap-2 align-items-center text-warning"
                                >
                                    <Fa icon={faWarning} />
                                    disabled
                                </span>
                            {:else}
                                {ipEcho.trustXForwardedHeaders ? 'enabled' : 'disabled'}
                            {/if}
                        </span>
                    </div>
                    <div class="list-group-item d-flex">
                        <span>Detected client IP</span>
                        <span class="ms-auto">
                            {#if !ipEcho.clientIp}
                                <span
                                    class="d-flex gap-2 align-items-center text-warning"
                                >
                                    <Fa icon={faWarning} />
                                    unknown
                                </span>
                            {:else}
                                <code>{ipEcho.clientIp}</code>
                            {/if}
                        </span>
                    </div>
                </div>
            {/snippet}
        </Loadable>
    {/if}
</div>
