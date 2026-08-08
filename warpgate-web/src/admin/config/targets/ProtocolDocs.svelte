<script lang="ts">
    import { faChevronRight } from '@fortawesome/free-solid-svg-icons'
    import { autosave } from 'common/autosave'
    import type { TargetKind } from 'gateway/lib/api'
    import snarkdown from 'snarkdown'
    import Fa from 'svelte-fa'
    import { protocolInfo } from './protocolInfo'

    interface Props {
        kind: TargetKind
    }

    const { kind }: Props = $props()

    const markdown = $derived(protocolInfo[kind])
    const html = $derived(markdown ? snarkdown(markdown) : undefined)

    const [open] = autosave('targetProtocolDocsOpen', true)
</script>

{#if html}
    <button
        type="button"
        class="p-0 d-flex align-items-center gap-2 text-start btn btn-link"
        onclick={e => {
            e.preventDefault()
            open.set(!$open)
        }}
    >
        <Fa fw icon={faChevronRight} rotate={$open ? 90 : 0} />
        <span>Protocol requirements &amp; supported features</span>
    </button>
    {#if $open}
        <div class="protocol-info-body small">{@html html}</div>
    {/if}
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
