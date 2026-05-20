<script lang="ts">
    import { link } from 'svelte-spa-router'
    import Badge from 'common/sveltestrap-s5-ports/Badge.svelte'
    import Fa from 'svelte-fa'
    import { faUser } from '@fortawesome/free-regular-svg-icons'

    export let id: string
    export let name: string
</script>

<Badge color="success" class="d-flex align-items-center">
    <Fa icon={faUser} class="me-2" />
    <a href="/config/users/{id}" use:link>{name}</a>
</Badge>
