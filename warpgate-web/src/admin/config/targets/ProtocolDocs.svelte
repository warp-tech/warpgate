<script lang="ts">
    import CollapsibleBlock from 'common/CollapsibleBlock.svelte'
    import type { TargetKind } from 'gateway/lib/api'
    import snarkdown from 'snarkdown'
    import { protocolInfo } from './protocolInfo'

    interface Props {
        kind: TargetKind
    }

    const { kind }: Props = $props()

    const markdown = $derived(protocolInfo[kind])
    const html = $derived(markdown ? snarkdown(markdown) : undefined)
</script>

{#if html}
    <CollapsibleBlock
        label="Protocol requirements & supported features"
        persistKey="targetProtocolDocsOpen"
        defaultOpen={true}
    >
        <div class="protocol-info-body small">{@html html}</div>
    </CollapsibleBlock>
{/if}

<style>
    .protocol-info-body {
        margin-top: 1.5rem;
        padding-left: 21px;

        :global(h2) {
            font-size: 1rem;
        }

        :global(p) {
            margin-bottom: 0.5rem;
        }

        :global(ul) {
            padding-left: 1rem;
        }
    }
</style>
