<script lang="ts">
    /**
     * List-level overflow menu — screen 13, chrome only.
     *
     * Behaviour preserved: renders nothing at all unless there is something
     * to show, and offers Collapse all / Expand all whenever the list is
     * grouped.
     *
     * Changed shape: sveltestrap's Dropdown took arbitrary markup as
     * children, so callers nested whatever they liked inside it — the portal
     * target list nested a switch. ui/Menu takes items as data, because roving
     * focus and type-ahead cannot be implemented over arbitrary markup. Extra
     * entries therefore arrive as `extraGroups` rather than as a snippet.
     *
     * That change is what lets the portal's "open targets in a new tab"
     * preference become a real `menuitemcheckbox` with `aria-checked`. Nested
     * inside a dropdown item it announced as neither a menu item nor a
     * checkbox, and its disabled state was explained by a tooltip that only
     * appeared on hover.
     */
    import type { MenuGroup } from 'ui/Menu.svelte'
    import Menu from 'ui/Menu.svelte'
    import type { GroupControls } from './ItemList.svelte'

    interface Props {
        groupControls: GroupControls
        extraGroups?: MenuGroup[]
        label?: string
    }

    const {
        groupControls,
        extraGroups = [],
        label = 'List options',
    }: Props = $props()

    const groups: MenuGroup[] = $derived([
        ...extraGroups,
        ...(groupControls.available
            ? [
                  {
                      label: 'Groups',
                      items: [
                          {
                              id: 'collapse-all',
                              label: 'Collapse all',
                              onselect: groupControls.collapseAll,
                          },
                          {
                              id: 'expand-all',
                              label: 'Expand all',
                              onselect: groupControls.expandAll,
                          },
                      ],
                  },
              ]
            : []),
    ])

    const hasAnything = $derived(groups.some(g => g.items.length > 0))
</script>

{#if hasAnything}
    <Menu {groups} {label} align="end" />
{/if}
