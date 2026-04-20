<script lang="ts">
    import { link } from 'svelte-spa-router'
    import Badge from 'common/sveltestrap-s5-ports/Badge.svelte'
    import Fa from 'svelte-fa'
    import { faCog } from '@fortawesome/free-solid-svg-icons'

    export let id: string
    export let name: string
</script>

<Badge color="info" class="d-flex align-items-center">
    <Fa icon={faCog} class="me-2" />
    <a href="/config/admin-roles/{id}" use:link>{name}</a>
</Badge>
