<script lang="ts">
    import { faComputer } from '@fortawesome/free-solid-svg-icons'
    import { Badge } from '@sveltestrap/sveltestrap'
    import Fa from 'svelte-fa'
    import { link } from 'svelte-spa-router'

    export let id: string
    export let name: string
</script>

<Badge color="primary" class="d-flex align-items-center">
    <Fa icon={faComputer} class="me-2" />
    <a href="/config/targets/{id}" use:link>{name}</a>
</Badge>
