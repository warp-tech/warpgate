import { BootstrapThemeColor, type GroupInfo } from 'gateway/lib/api'
import { compare as naturalCompareFactory } from 'natural-orderby'
import { firstBy } from 'thenby'

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

export interface GroupedOrder<T> {
    groupId: (item: T) => string | undefined
    groupName: (item: T) => string
    name: (item: T) => string
}

/**
 * Order items for a grouped `ItemList`, which groups by adjacency.
 *
 * A search result keeps the server's relevance order and only pulls each group
 * together, so groups come in order of their best match. Otherwise ungrouped
 * items go last, and groups and the items within them sort naturally.
 */
export function orderForGroupedList<T>(
    items: T[],
    search: string | undefined,
    order: GroupedOrder<T>,
): T[] {
    if (search) {
        return [...Map.groupBy(items, order.groupId).values()].flat()
    }
    const natural = naturalCompareFactory()
    return items.sort(
        firstBy((item: T) => !order.groupId(item))
            .thenBy((a: T, b: T) =>
                natural(
                    order.groupName(a).toLowerCase(),
                    order.groupName(b).toLowerCase(),
                ),
            )
            .thenBy((a: T, b: T) =>
                natural(
                    order.name(a).toLowerCase(),
                    order.name(b).toLowerCase(),
                ),
            ),
    )
}
