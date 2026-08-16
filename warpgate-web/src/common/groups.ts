import { BootstrapThemeColor, type GroupInfo } from 'gateway/lib/api'

// Synthetic group for items that have none. `$` can't start a UUID, so this
// never collides with a real group's ID.
export const UNGROUPED_ID = '$ungrouped'

export interface ResolvedGroup {
    id: string
    name: string
    color: BootstrapThemeColor
}

export function resolveGroup(group: GroupInfo | undefined): ResolvedGroup {
    if (!group) {
        return {
            id: UNGROUPED_ID,
            name: 'Ungrouped',
            color: BootstrapThemeColor.Secondary,
        }
    }
    return {
        id: group.id,
        name: group.name,
        color: group.color ?? BootstrapThemeColor.Secondary,
    }
}
