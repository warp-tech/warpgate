import { api } from 'admin/lib/api'
import type { AdminPermissions } from 'gateway/lib/api'
import type { PaletteEntity } from './CommandPalette.svelte'

/**
 * Loads the things the palette searches over: targets, users and recent
 * sessions.
 *
 * Gated on the same ADMIN_PERMISSIONS keys as the nav and the action registry.
 * This matters more here than anywhere else — the palette would otherwise
 * *fetch* a list the operator has no right to see, so the gate is on the
 * request, not on the rendering.
 *
 * Loaded once, lazily, on first open rather than at shell mount: an operator
 * who never presses Cmd+K should not pay three list requests for it. Sessions
 * are capped because the palette is for finding a known thing, not for
 * browsing — the sessions screen exists for that.
 */

const SESSION_LIMIT = 100

export interface EntityLoadResult {
    entities: PaletteEntity[]
    /** Requests that failed, by group, so the palette can say so. */
    failed: string[]
}

function centreTruncate(value: string, max = 28): string {
    if (value.length <= max) {
        return value
    }
    const half = Math.floor((max - 1) / 2)
    return `${value.slice(0, half)}…${value.slice(-half)}`
}

export async function loadPaletteEntities(
    permissions: AdminPermissions,
): Promise<EntityLoadResult> {
    const entities: PaletteEntity[] = []
    const failed: string[] = []

    const jobs: Promise<void>[] = []

    if (permissions.targetsEdit) {
        jobs.push(
            api
                .getTargets({})
                .then(targets => {
                    for (const target of targets) {
                        entities.push({
                            id: `target:${target.id}`,
                            label: target.name,
                            detail: target.description || undefined,
                            group: 'Targets',
                            href: `#/config/targets/${target.id}`,
                            mono: true,
                        })
                    }
                })
                .catch(() => {
                    failed.push('Targets')
                }),
        )
    }

    if (permissions.usersEdit) {
        jobs.push(
            api
                .getUsers({})
                .then(users => {
                    for (const user of users) {
                        entities.push({
                            id: `user:${user.id}`,
                            label: user.username,
                            detail: user.description || undefined,
                            group: 'Users',
                            href: `#/config/users/${user.id}`,
                            mono: true,
                        })
                    }
                })
                .catch(() => {
                    failed.push('Users')
                }),
        )
    }

    if (permissions.sessionsView) {
        jobs.push(
            api
                .getSessions({ limit: SESSION_LIMIT, offset: 0 })
                .then(response => {
                    for (const session of response.items) {
                        const target =
                            session.targetSessions?.[0]?.target?.name ?? ''
                        entities.push({
                            id: `session:${session.id}`,
                            label:
                                session.username || centreTruncate(session.id),
                            detail: [
                                target,
                                session.protocol,
                                session.remoteAddress,
                            ]
                                .filter(Boolean)
                                .join(' · '),
                            group: session.ended
                                ? 'Sessions (ended)'
                                : 'Sessions (live)',
                            href: `#/status/sessions/${session.id}`,
                            mono: true,
                        })
                    }
                })
                .catch(() => {
                    failed.push('Sessions')
                }),
        )
    }

    await Promise.all(jobs)
    return { entities, failed }
}
