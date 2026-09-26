<script lang="ts">
    import { faUser } from '@fortawesome/free-regular-svg-icons'
    import { Badge } from '@sveltestrap/sveltestrap'
    import { adminPermissions } from 'admin/lib/store'
    import Fa from 'svelte-fa'

    export let id: string | undefined
    export let name: string
</script>

<Badge
    href={$adminPermissions.usersEdit && id ? `#/config/users/${id}` : undefined}
    color="success"
    class="d-flex align-items-center"
>
    <Fa icon={faUser} class="me-2" />
    {name}
</Badge>
