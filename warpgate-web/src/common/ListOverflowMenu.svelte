<script lang="ts">
    import { faCheck, faEllipsisV } from '@fortawesome/free-solid-svg-icons'
    import {
        Dropdown,
        DropdownItem,
        DropdownMenu,
        DropdownToggle,
    } from '@sveltestrap/sveltestrap'
    import type { Snippet } from 'svelte'
    import Fa from 'svelte-fa'
    import type { ColumnControls, GroupControls } from './ItemList.svelte'

    interface Props {
        groupControls: GroupControls
        columnControls?: ColumnControls
        children?: Snippet
    }

    const { groupControls, columnControls, children }: Props = $props()

    const columns = $derived(columnControls?.toggleable ?? [])
</script>

{#if children || groupControls.available || columns.length}
    <Dropdown>
        <DropdownToggle color="link">
            <Fa icon={faEllipsisV} fw />
        </DropdownToggle>
        <DropdownMenu end>
            {@render children?.()}
            {#if columns.length}
                <div class="dropdown-header">Columns</div>
                {#each columns as column (column.id)}
                    <DropdownItem
                        toggle={false}
                        onclick={() => columnControls?.toggle(column.id)}
                    >
                        <Fa
                            icon={faCheck}
                            fw
                            class={column.shown ? '' : 'invisible'}
                        />
                        {column.label}
                    </DropdownItem>
                {/each}
            {/if}
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
