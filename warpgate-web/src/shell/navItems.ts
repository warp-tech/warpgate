import type { AdminPermissionKey } from 'admin/lib/store'
import type { AdminPermissions } from 'gateway/lib/api'

/**
 * Sidebar navigation, gated on the same ADMIN_PERMISSIONS keys the palette
 * uses. One list, one gate — a nav item the operator cannot reach is absent,
 * not disabled, for the same disclosure reason.
 *
 * `icon` is a path drawn on a 16×16 viewBox. Icons are inline paths rather
 * than a FontAwesome import because the collapsed rail renders them at every
 * route and the existing @fortawesome packages are only pulled in by screens
 * that have not migrated yet.
 */

export interface NavItem {
    id: string
    label: string
    href: string
    /** Route prefix that marks this item active. */
    match: string
    icon: string
    requires?: AdminPermissionKey
}

export interface NavSection {
    id: string
    label: string
    items: NavItem[]
}

const ICONS = {
    sessions: 'M2 4h12M2 8h12M2 12h8',
    requests: 'M8 2v6l4 2M8 14A6 6 0 108 2a6 6 0 000 12z',
    shield: 'M8 2l5 2v4c0 3-2 5.5-5 6-3-.5-5-3-5-6V4l5-2z',
    network: 'M8 2v4M8 10v4M3 8h10M4 5l8 6M12 5l-8 6',
    log: 'M4 2h8v12H4zM6 5h4M6 8h4M6 11h2',
    target: 'M8 2a6 6 0 100 12A6 6 0 008 2zm0 3a3 3 0 100 6 3 3 0 000-6z',
    group: 'M3 4h4v4H3zM9 4h4v4H9zM3 10h4v4H3zM9 10h4v4H9z',
    user: 'M8 8a3 3 0 100-6 3 3 0 000 6zM2 14c0-3 2.5-4.5 6-4.5S14 11 14 14',
    key: 'M10 2a4 4 0 00-3.5 6L2 12.5V14h2l.5-1.5H6V11h1.5l.5-.5A4 4 0 1010 2z',
    ticket: 'M2 5h12v2a1.5 1.5 0 000 3v2H2v-2a1.5 1.5 0 000-3z',
    sliders: 'M2 5h8M12 5h2M2 11h2M6 11h8M10 3v4M4 9v4',
    directory: 'M2 3h5l1 2h6v8H2z',
}

export const NAV_SECTIONS: NavSection[] = [
    {
        id: 'status',
        label: 'Status',
        items: [
            {
                id: 'sessions',
                label: 'Sessions',
                href: '#/status/sessions',
                match: '/status/sessions',
                icon: ICONS.sessions,
                requires: 'sessionsView',
            },
            {
                id: 'requests',
                label: 'Requests',
                href: '#/status/requests',
                match: '/status/requests',
                icon: ICONS.requests,
                requires: 'approveSessions',
            },
            {
                id: 'login-protection',
                label: 'Login protection',
                href: '#/status/login-protection',
                match: '/status/login-protection',
                icon: ICONS.shield,
                requires: 'configEdit',
            },
            {
                id: 'network',
                label: 'Network',
                href: '#/status/network',
                match: '/status/network',
                icon: ICONS.network,
                requires: 'configEdit',
            },
            {
                id: 'log',
                label: 'Audit log',
                href: '#/log',
                match: '/log',
                icon: ICONS.log,
                requires: 'sessionsView',
            },
        ],
    },
    {
        id: 'access',
        label: 'Access',
        items: [
            {
                id: 'targets',
                label: 'Targets',
                href: '#/config/targets',
                match: '/config/targets',
                icon: ICONS.target,
                requires: 'targetsEdit',
            },
            {
                id: 'target-groups',
                label: 'Target groups',
                href: '#/config/target-groups',
                match: '/config/target-groups',
                icon: ICONS.group,
                requires: 'targetsEdit',
            },
            {
                id: 'users',
                label: 'Users',
                href: '#/config/users',
                match: '/config/users',
                icon: ICONS.user,
                requires: 'usersEdit',
            },
            {
                id: 'access-roles',
                label: 'Access roles',
                href: '#/config/access-roles',
                match: '/config/access-roles',
                icon: ICONS.shield,
                requires: 'accessRolesEdit',
            },
            {
                id: 'admin-roles',
                label: 'Admin roles',
                href: '#/config/admin-roles',
                match: '/config/admin-roles',
                icon: ICONS.shield,
                requires: 'adminRolesManage',
            },
            {
                id: 'tickets',
                label: 'Tickets',
                href: '#/config/tickets',
                match: '/config/tickets',
                icon: ICONS.ticket,
                requires: 'ticketsCreate',
            },
        ],
    },
    {
        id: 'configuration',
        label: 'Configuration',
        items: [
            {
                id: 'ssh',
                label: 'SSH keys',
                href: '#/config/ssh',
                match: '/config/ssh',
                icon: ICONS.key,
                requires: 'configEdit',
            },
            {
                id: 'policies',
                label: 'Policies',
                href: '#/config/policies',
                match: '/config/policies',
                icon: ICONS.shield,
                requires: 'configEdit',
            },
            {
                id: 'ldap',
                label: 'LDAP servers',
                href: '#/config/ldap-servers',
                match: '/config/ldap-servers',
                icon: ICONS.directory,
                requires: 'configEdit',
            },
            {
                id: 'parameters',
                label: 'Parameters',
                href: '#/config/parameters',
                match: '/config/parameters',
                icon: ICONS.sliders,
                requires: 'configEdit',
            },
        ],
    },
]

export function permittedSections(
    sections: NavSection[],
    permissions: AdminPermissions,
): NavSection[] {
    return sections
        .map(section => ({
            ...section,
            items: section.items.filter(
                item => !item.requires || permissions[item.requires] === true,
            ),
        }))
        .filter(section => section.items.length > 0)
}

/**
 * Longest-prefix match, so `/config/targets/abc` highlights Targets rather
 * than matching nothing, and `/config/target-groups` is not captured by
 * `/config/targets`.
 */
export function activeItemId(
    sections: NavSection[],
    path: string,
): string | undefined {
    let best: NavItem | undefined
    for (const section of sections) {
        for (const item of section.items) {
            const exact = path === item.match
            const child = path.startsWith(`${item.match}/`)
            if (
                (exact || child) &&
                (!best || item.match.length > best.match.length)
            ) {
                best = item
            }
        }
    }
    return best?.id
}
