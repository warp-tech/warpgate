import type { UserSessionSnapshot } from 'admin/lib/api'

export interface SessionGroup {
    /** Stable across reloads while the group's oldest session stays loaded */
    key: string
    /** Newest first, like the list they come from */
    sessions: UserSessionSnapshot[]
}

export function newestSession(group: SessionGroup): UserSessionSnapshot {
    // biome-ignore lint/style/noNonNullAssertion: groups are never empty
    return group.sessions[0]!
}

export function oldestSession(group: SessionGroup): UserSessionSnapshot {
    // biome-ignore lint/style/noNonNullAssertion: groups are never empty
    return group.sessions.at(-1)!
}

/**
 * Sessions are grouped when they come from the same user and reached the same
 * set of targets. Anonymous sessions and sessions that never reached a target
 * stay on their own.
 */
function groupingKey(session: UserSessionSnapshot): string | null {
    if (!session.username) {
        return null
    }
    const targetIds = [
        ...new Set(session.targetSessions.map(t => t.targetId)),
    ].sort()
    if (!targetIds.length) {
        return null
    }
    return `${session.username}\0${targetIds.join(',')}`
}

/**
 * Merges sessions of the same user and target(s) that are less than
 * `windowMs` apart (from the end of one to the start of the next). Overlapping
 * sessions, such as parallel automation runs, always merge.
 *
 * `sessions` must be sorted newest first; the groups keep that order, each
 * placed where its newest session was.
 */
export function groupSessions(
    sessions: UserSessionSnapshot[],
    windowMs: number,
    now: Date = new Date(),
): SessionGroup[] {
    const groups: SessionGroup[] = []
    const openGroups = new Map<string, SessionGroup>()

    for (const session of sessions) {
        const key = groupingKey(session)
        if (key === null) {
            groups.push({ key: session.id, sessions: [session] })
            continue
        }

        const group = openGroups.get(key)
        if (group) {
            const gap =
                new Date(oldestSession(group).started).getTime() -
                new Date(session.ended ?? now).getTime()
            if (gap <= windowMs) {
                group.sessions.push(session)
                group.key = `${key}\0${session.id}`
                continue
            }
        }

        const newGroup = { key: `${key}\0${session.id}`, sessions: [session] }
        groups.push(newGroup)
        openGroups.set(key, newGroup)
    }

    return groups
}
