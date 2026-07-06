<script lang="ts">
    import { faCog } from '@fortawesome/free-solid-svg-icons'
    import { Badge } from '@sveltestrap/sveltestrap'
    import Fa from 'svelte-fa'
    import { link } from 'svelte-spa-router'

    export let id: string
    export let name: string
    export let type: 'access' | 'admin' = 'access'

    const path = type === 'admin' ? 'admin-roles' : 'access-roles'
    const color = type === 'admin' ? 'info' : 'warning'
</script>

<Badge {color} class="d-flex align-items-center">
    <Fa icon={faCog} class="me-2" />
    <a href="/config/{path}/{id}" use:link>{name}</a>
</Badge>
