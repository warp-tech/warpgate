<script lang="ts">
    import { TargetKind } from 'gateway/lib/api'
    import NavListItem from 'common/NavListItem.svelte'
    import Badge from 'common/sveltestrap-s5-ports/Badge.svelte';

    const kinds: {
        name: string,
        value: TargetKind,
        description: string,
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
            description: 'Expose Kubernetes API protocol for tools like kubectl',
            experimental: true,
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
                title={kind.name}
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
