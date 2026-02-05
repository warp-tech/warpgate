<script lang="ts">
    import { TargetKind } from 'gateway/lib/api'
    import NavListItem from 'common/NavListItem.svelte'

    const kinds: { name: string, value: TargetKind, description: string }[] = [
        { name: 'SSH', value: TargetKind.Ssh, description: 'Expose access to shell, SFTP and port forwarding' },
        { name: 'HTTP', value: TargetKind.Http, description: 'Warpgate will act as a reverse proxy' },
        { name: 'MySQL', value: TargetKind.MySql, description: 'Expose access to a database server' },
        { name: 'PostgreSQL', value: TargetKind.Postgres, description: 'Expose access to a database server' },
        { name: 'Kubernetes', value: TargetKind.Kubernetes, description: 'Expose Kubernetes API protocol for tools like kubectl' },
    ]
</script>

<div class="container-max-md">
    <div class="page-summary-bar">
        <h1>add a target</h1>
    </div>

    <div class="narrow-page">
        {#each kinds as kind (kind.value)}/Users/eugene/Work/warpgate/warpgate-web/src/admin/config/targets/ChooseTargetKind.svelte
            <NavListItem
                title={kind.name}
                description={kind.description}
                href={`/config/targets/create/${kind.value}`}
            />
        {/each}
    </div>
</div>
