<script lang="ts">
    import { faEllipsisV } from '@fortawesome/free-solid-svg-icons'
    import {
        Dropdown,
        DropdownItem,
        DropdownMenu,
        DropdownToggle,
    } from '@sveltestrap/sveltestrap'
    import type { Snippet } from 'svelte'
    import Fa from 'svelte-fa'
    import type { GroupControls } from './ItemList.svelte'

    interface Props {
        groupControls: GroupControls
        children?: Snippet
    }

    const { groupControls, children }: Props = $props()
</script>

{#if children || groupControls.available}
    <Dropdown>
        <DropdownToggle color="link">
            <Fa icon={faEllipsisV} fw />
        </DropdownToggle>
        <DropdownMenu end>
            {@render children?.()}
            {#if groupControls.available}
                <div class="dropdown-header">Groups</div>
                <DropdownItem onclick={groupControls.collapseAll}>
                    Collapse all
                </DropdownItem>
                <DropdownItem onclick={groupControls.expandAll}>
                    Expand all
                </DropdownItem>
            {/if}
        </DropdownMenu>
    </Dropdown>
{/if}
