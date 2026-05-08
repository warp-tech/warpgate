<script lang="ts">
    import { link } from 'svelte-spa-router'
    import Badge from 'common/sveltestrap-s5-ports/Badge.svelte'
    import Fa from 'svelte-fa'
    import { faComputer } from '@fortawesome/free-solid-svg-icons'

    export let id: string
    export let name: string
</script>

<Badge color="primary" class="d-flex align-items-center">
    <Fa icon={faComputer} class="me-2" />
    <a href="/config/targets/{id}" use:link>{name}</a>
</Badge>
