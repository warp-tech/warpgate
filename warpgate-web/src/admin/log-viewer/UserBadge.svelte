<script lang="ts">
    import { faUser } from '@fortawesome/free-regular-svg-icons'
    import { Badge } from '@sveltestrap/sveltestrap'
    import Fa from 'svelte-fa'
    import { link } from 'svelte-spa-router'

    export let id: string
    export let name: string
</script>

<Badge color="success" class="d-flex align-items-center">
    <Fa icon={faUser} class="me-2" />
    <a href="/config/users/{id}" use:link>{name}</a>
</Badge>
