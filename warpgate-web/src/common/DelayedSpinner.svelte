<script lang="ts">
import { Spinner } from 'sveltestrap'

let visible = false

setTimeout(() => {
    visible = true
}, 1000)
</script>

{#if visible}
<Spinner style="margin: 3rem auto" />
{/if}
