import type { Crumb } from 'shell/Breadcrumbs.svelte'
import { NAV_SECTIONS } from 'shell/navItems'

/**
 * Derives the breadcrumb trail from the SPA path.
 *
 * Built from NAV_SECTIONS rather than a parallel table, so a renamed nav item
 * renames its crumb too. The leaf — a target name, a username — is not known
 * from the route, so screens pass it in and it is appended.
 */

const LEAF_LABELS: Record<string, string> = {
    create: 'New',
    users: 'Users',
    credentials: 'Credentials',
}

export function crumbsFor(path: string, leaf?: Crumb): Crumb[] {
    const crumbs: Crumb[] = []

    for (const section of NAV_SECTIONS) {
        for (const item of section.items) {
            if (path === item.match || path.startsWith(`${item.match}/`)) {
                crumbs.push({
                    label: item.label,
                    href: path === item.match ? undefined : item.href,
                })
            }
        }
    }

    // Longest match wins, same rule the sidebar highlight uses.
    if (crumbs.length > 1) {
        crumbs.splice(0, crumbs.length - 1)
    }

    if (leaf) {
        crumbs.push(leaf)
        return crumbs
    }

    // A trailing segment with a known label (…/create) becomes its own crumb.
    const tail = path.split('/').filter(Boolean).pop()
    if (tail && LEAF_LABELS[tail] && crumbs.length) {
        crumbs.push({ label: LEAF_LABELS[tail] })
    }

    return crumbs
}
