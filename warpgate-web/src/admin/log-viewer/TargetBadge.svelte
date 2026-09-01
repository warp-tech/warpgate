<script lang="ts">
    import { faComputer } from '@fortawesome/free-solid-svg-icons'
    import { Badge } from '@sveltestrap/sveltestrap'
    import { adminPermissions } from 'admin/lib/store'
    import Fa from 'svelte-fa'

    export let id: string | undefined
    export let name: string
</script>

<Badge
    href={$adminPermissions.targetsEdit && id ? `#/config/targets/${id}` : undefined}
    color="info"
    class="d-flex align-items-center gap-2"
>
    <Fa icon={faComputer} />
    {name}
</Badge>
