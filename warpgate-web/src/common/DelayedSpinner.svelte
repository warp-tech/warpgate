<script lang="ts">
import { Spinner } from '@sveltestrap/sveltestrap'

let visible = $state(false)

setTimeout(() => {
    visible = true
}, 1000)
</script>

{#if visible}
<Spinner style="margin: 3rem auto" />
{/if}
