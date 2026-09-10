<script lang="ts">
    import { faChevronRight, faCircle } from '@fortawesome/free-solid-svg-icons'
    import GroupColorIcon from './GroupColorIcon.svelte'
    import type { ResolvedGroup } from './groups'
    import type { GroupState } from './ItemList.svelte'

    interface Props {
        group: ResolvedGroup
        state: GroupState
    }

    const { group, state }: Props = $props()
</script>

{#snippet label()}
    <GroupColorIcon color={group.color} collapsed={state.collapsed} />
    <span class="h5 mb-0">{group.name}</span>
{/snippet}

{#if state.collapsible}
    <button
        type="button"
        class="btn btn-link text-decoration-none d-flex align-items-center gap-2 p-0 text-start mb-2 mt-4"
        aria-expanded={!state.collapsed}
        onclick={state.toggle}
    >
        {@render label()}
    </button>
{:else}
    <div class="d-flex align-items-center gap-2 mb-2 mt-4">
        {@render label()}
    </div>
{/if}
