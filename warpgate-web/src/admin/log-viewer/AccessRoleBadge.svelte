<script lang="ts">
    import { faCog } from '@fortawesome/free-solid-svg-icons'
    import { Badge } from '@sveltestrap/sveltestrap'
    import Fa from 'svelte-fa'
    import { link } from 'svelte-spa-router'

    export let id: string
    export let name: string
</script>

<Badge color="warning" class="d-flex align-items-center">
    <Fa icon={faCog} class="me-2" />
    <a href="/config/access-roles/{id}" use:link>{name}</a>
</Badge>
