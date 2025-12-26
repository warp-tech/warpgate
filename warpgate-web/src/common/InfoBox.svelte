<script lang="ts">
    import { faInfoCircle } from '@fortawesome/free-solid-svg-icons'
    import Fa from 'svelte-fa'
    import type { Snippet } from 'svelte'

    interface Props {
        class?: string,
        children: Snippet,
    }

    // eslint-disable-next-line svelte/no-unused-props
    let {
        children,
        'class': className = 'mt-3 mb-4',
    }: Props = $props()
</script>

<div class="text-muted d-flex gap-2 align-items-center {className}">
    <Fa icon={faInfoCircle} />
    <small>
        {@render children()}
    </small>
</div>


<style>
    div {
        line-height: 1;
    }
</style>
