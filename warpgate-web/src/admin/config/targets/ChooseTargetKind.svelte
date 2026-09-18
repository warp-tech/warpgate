<script lang="ts">
    /**
     * Pick a target protocol — restyled in place.
     *
     * Behaviour preserved: the same seven kinds in the same order, the same
     * descriptions, the same three marked experimental, and the same
     * /config/targets/create/<kind> destinations.
     *
     * common/NavListItem is dropped here rather than migrated: it is shared
     * with two other old-UI screens and is not sveltestrap, so restyling it
     * would churn them for no deletion benefit. This is the same call made on
     * the portal profile hub.
     */
    import { TargetKind } from 'gateway/lib/api'
    import Badge from 'ui/Badge.svelte'
    import 'ui/layout.css'
    import { link } from 'svelte-spa-router'

    const kinds: {
        name: string
        value: TargetKind
        description: string
        experimental?: boolean
    }[] = [
        {
            name: 'SSH',
            value: TargetKind.Ssh,
            description: 'Expose access to shell, SFTP and port forwarding',
        },
        {
            name: 'HTTP',
            value: TargetKind.Http,
            description: 'Warpgate will act as a reverse proxy',
        },
        {
            name: 'MySQL',
            value: TargetKind.MySql,
            description: 'Expose access to a database server',
        },
        {
            name: 'PostgreSQL',
            value: TargetKind.Postgres,
            description: 'Expose access to a database server',
        },
        {
            name: 'Kubernetes',
            value: TargetKind.Kubernetes,
            description:
                'Expose Kubernetes API protocol for tools like kubectl',
            experimental: true,
        },
        {
            name: 'VNC',
            value: TargetKind.Vnc,
            description: 'Access a remote desktop in the browser',
            experimental: true,
        },
        {
            name: 'RDP',
            value: TargetKind.Rdp,
            description: 'Access a Windows remote desktop in the browser',
            experimental: true,
        },
    ]
</script>

<div class="wg-page-narrow">
    <div class="wg-page-head">
        <h1>Add a target</h1>
    </div>

    <ul class="wg-rows">
        {#each kinds as kind (kind.value)}
            <li>
                <a
                    class="wg-row-link"
                    href="/config/targets/create/{kind.value}"
                    use:link
                >
                    <span class="kind-text">
                        <span class="kind-name">
                            <strong>{kind.name}</strong>
                            {#if kind.experimental}
                                <Badge tone="warning">Experimental</Badge>
                            {/if}
                        </span>
                        <small>{kind.description}</small>
                    </span>
                    <span class="go" aria-hidden="true">→</span>
                </a>
            </li>
        {/each}
    </ul>
</div>

<style>
    .kind-text {
        display: flex;
        flex-direction: column;
        gap: 2px;
        min-width: 0;
        margin-right: auto;
    }

    .kind-name {
        display: flex;
        align-items: center;
        gap: var(--wg-space-sm);
    }

    .kind-text small {
        color: var(--wg-text-muted);
        font: var(--wg-text-label-sm);
    }

    .go {
        flex: none;
        color: var(--wg-text-muted);
    }
</style>
