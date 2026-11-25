<script lang="ts">
    import { faBolt } from '@fortawesome/free-solid-svg-icons'
    import { serverInfo } from 'gateway/lib/store'
    import type { Snippet } from 'svelte'
    import InfoBox from './InfoBox.svelte'

    interface Props {
        children: Snippet
    }

    let { children }: Props = $props()
</script>

{#if $serverInfo?.setupState}
    <InfoBox variant="success" icon={faBolt}> {@render children()} </InfoBox>
{/if}
