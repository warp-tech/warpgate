<script lang="ts">
    import { onMount } from 'svelte'
    import { replace } from 'svelte-spa-router'

    let { to }: { to: string } = $props()

    onMount(() => replace(to))
</script>
