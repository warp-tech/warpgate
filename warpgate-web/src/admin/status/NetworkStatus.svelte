<script lang="ts">
    /**
     * Network status — restyled in place.
     *
     * Behaviour preserved exactly, including the parts that are easy to lose:
     *   - the three listener states and their tones
     *   - the per-listener error, shown only when present
     *   - the certificate labelling rule: "Certificate" when a listener has
     *     one, "Default certificate" for the first of several and "SNI
     *     certificate" for the rest
     *   - an expiry in the past rendered in the error colour
     *   - the four IP-detection rows, each with its own warning condition.
     *     "Trust X-Forwarded-* headers" warns only when the header is present
     *     AND untrusted, which is the case that silently breaks audit and
     *     login protection; disabled with no header present is normal.
     *
     * The warnings were an amber FontAwesome triangle with no text
     * alternative. They are StatusMarkers now, which carry a label.
     */
    import { api, ListenerState } from 'admin/lib/api'
    import HelpText from 'admin/lib/HelpText.svelte'
    import Loadable from 'common/Loadable.svelte'
    import type { BadgeTone } from 'ui/Badge.svelte'
    import Badge from 'ui/Badge.svelte'
    import Callout from 'ui/Callout.svelte'
    import 'ui/layout.css'
    import RelativeDate from 'ui/RelativeDate.svelte'
    import StatusMarker from 'ui/StatusMarker.svelte'

    const stateTones: Record<ListenerState, BadgeTone> = {
        [ListenerState.Listening]: 'success',
        [ListenerState.Disabled]: 'neutral',
        [ListenerState.BindFailed]: 'danger',
    }

    function certLabel(total: number, index: number): string {
        if (total <= 1) {
            return 'Certificate'
        }
        return index === 0 ? 'Default certificate' : 'SNI certificate'
    }
</script>

<div class="wg-page-head">
    <h1>Network status</h1>
</div>

<section>
    <h2>Protocol listeners</h2>
    <Loadable promise={api.getListenerStates()}>
        {#snippet children(listeners)}
            <ul class="wg-rows listeners">
                {#each listeners as listener (listener.name)}
                    <li>
                        <div class="listener">
                            <div class="listener-head">
                                <Badge tone={stateTones[listener.state]}>
                                    {listener.state}
                                </Badge>
                                <strong>{listener.name}</strong>
                                <code class="addr">{listener.address}</code>
                            </div>

                            {#if listener.error}
                                <div class="listener-error">
                                    <Callout
                                        tone="danger"
                                        title="This listener failed to bind"
                                    >
                                        {listener.error}
                                    </Callout>
                                </div>
                            {/if}

                            {#each listener.certificates as cert, index (cert.domains.join(','))}
                                <small class="cert">
                                    {certLabel(
                                        listener.certificates.length,
                                        index,
                                    )}:
                                    {cert.domains.join(', ')}
                                    {#if cert.expiry}
                                        &middot;
                                        <span
                                            class:expired={cert.expiry <
                                                new Date()}
                                        >
                                            expires
                                            <RelativeDate date={cert.expiry} />
                                        </span>
                                    {/if}
                                </small>
                            {/each}
                        </div>
                    </li>
                {/each}
            </ul>
        {/snippet}
    </Loadable>
</section>

<section>
    <h2>Client IP detection</h2>
    <p class="wg-page-lede">
        Exactly how this client's IP is being detected by Warpgate.
    </p>
    <HelpText>
        Your setup must ensure that Warpgate can see the actual client's IP
        address instead of the IP of a reverse proxy or a load balancer. This
        ensures that both audit and login protection will work correctly.
    </HelpText>

    <Loadable promise={api.getIpEcho()}>
        {#snippet children(ipEcho)}
            <ul class="wg-rows">
                <li>
                    <span class="label">Peer IP as seen by the server</span>
                    <span class="value">
                        {#if ipEcho.peerIp}
                            <code>{ipEcho.peerIp}</code>
                        {:else}
                            <StatusMarker kind="pending" label="Unknown" bare />
                        {/if}
                    </span>
                </li>
                <li>
                    <span class="label">X-Forwarded-For header value</span>
                    <span class="value">
                        {#if ipEcho.xForwardedFor}
                            <code>{ipEcho.xForwardedFor}</code>
                        {:else}
                            <span class="muted">not present</span>
                        {/if}
                    </span>
                </li>
                <li>
                    <span class="label">Trust X-Forwarded-* headers</span>
                    <span class="value">
                        {#if !ipEcho.trustXForwardedHeaders && ipEcho.xForwardedFor}
                            <StatusMarker
                                kind="pending"
                                label="Disabled, but the header is present"
                                bare
                            />
                        {:else}
                            {ipEcho.trustXForwardedHeaders
                                ? 'enabled'
                                : 'disabled'}
                        {/if}
                    </span>
                </li>
                <li>
                    <span class="label">Detected client IP</span>
                    <span class="value">
                        {#if ipEcho.clientIp}
                            <code>{ipEcho.clientIp}</code>
                        {:else}
                            <StatusMarker kind="pending" label="Unknown" bare />
                        {/if}
                    </span>
                </li>
            </ul>
        {/snippet}
    </Loadable>
</section>

<style>
    section {
        margin-bottom: var(--wg-space-2xl);
    }

    h2 {
        margin: 0 0 var(--wg-space-md);
        font: var(--wg-text-headline-md);
    }

    .listeners > li {
        align-items: flex-start;
    }

    .listener {
        display: flex;
        flex-direction: column;
        gap: var(--wg-space-xs);
        width: 100%;
        min-width: 0;
    }

    .listener-head {
        display: flex;
        align-items: center;
        gap: var(--wg-space-sm);
        flex-wrap: wrap;
    }

    .addr {
        margin-left: auto;
        color: var(--wg-text-muted);
        font: var(--wg-text-code-sm);
    }

    .listener-error {
        margin: var(--wg-space-xs) 0;
    }

    .cert {
        color: var(--wg-text-muted);
        font: var(--wg-text-label-sm);
    }

    .expired {
        color: var(--wg-error);
    }

    .label {
        margin-right: auto;
        font: var(--wg-text-body-md);
    }

    .value {
        flex: none;
        font: var(--wg-text-body-md);
    }

    .muted {
        color: var(--wg-text-muted);
    }

    code {
        font: var(--wg-text-code-sm);
        color: var(--wg-text);
    }
</style>
