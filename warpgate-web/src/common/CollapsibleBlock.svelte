<script lang="ts">
    import { faChevronRight } from '@fortawesome/free-solid-svg-icons'
    import type { Snippet } from 'svelte'
    import Fa from 'svelte-fa'
    import { autosave } from 'common/autosave'

    interface Props {
        label: string
        persistKey: string
        defaultOpen?: boolean
        children: Snippet
    }

    const { label, persistKey, defaultOpen = false, children }: Props = $props()

    // svelte-ignore state_referenced_locally -- both are fixed at mount
    const [open] = autosave(persistKey, defaultOpen)
</script>

<button
    type="button"
    class="p-0 d-flex align-items-center gap-2 text-start btn btn-link"
    onclick={e => {
        e.preventDefault()
        open.set(!$open)
    }}
>
    <Fa fw icon={faChevronRight} rotate={$open ? 90 : 0} />
    <span>{label}</span>
</button>
{#if $open}
    {@render children()}
{/if}
