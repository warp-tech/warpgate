<script lang="ts">
    import { Badge } from '@sveltestrap/sveltestrap'
    import NavListItem from 'common/NavListItem.svelte'
    import { TARGET_KIND_LABELS } from 'common/targetKinds'
    import { TargetKind } from 'gateway/lib/api'

    const kinds: {
        value: TargetKind
        description: string
        experimental?: boolean
    }[] = [
        {
            value: TargetKind.Ssh,
            description: 'Expose access to shell, SFTP and port forwarding',
        },
        {
            value: TargetKind.Http,
            description: 'Warpgate will act as a reverse proxy',
        },
        {
            value: TargetKind.MySql,
            description: 'Expose access to a database server',
        },
        {
            value: TargetKind.Postgres,
            description: 'Expose access to a database server',
        },
        {
            value: TargetKind.Kubernetes,
            description:
                'Expose Kubernetes API protocol for tools like kubectl',
        },
        {
            value: TargetKind.Vnc,
            description: 'Access a remote desktop in the browser',
        },
        {
            value: TargetKind.Rdp,
            description: 'Access a Windows remote desktop in the browser',
        },
    ]
</script>

<div class="container-max-md">
    <div class="page-summary-bar">
        <h1>add a target</h1>
    </div>

    <div class="narrow-page">
        {#each kinds as kind (kind.value)}
            <NavListItem
                title={TARGET_KIND_LABELS[kind.value]}
                description={kind.description}
                href={`/config/targets/create/${kind.value}`}
            >
                {#snippet addonSnippet()}
                    {#if kind.experimental}
                        <Badge color="warning">Experimental</Badge>
                    {/if}
                {/snippet}
            </NavListItem>
        {/each}
    </div>
</div>
