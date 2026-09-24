import type { AdminPermissionKey } from 'admin/lib/store'
import type { AdminPermissions } from 'gateway/lib/api'

/**
 * The command palette's action registry.
 *
 * Every action names a key from `admin/lib/store`'s ADMIN_PERMISSIONS —
 * there is deliberately no second permission list here. Surfacing an action
 * the operator cannot perform leaks the shape of the system: a palette that
 * lists "Terminate session" to someone without `sessionsTerminate` tells them
 * the capability exists and who might hold it. Actions the operator lacks are
 * filtered out, not disabled.
 *
 * `requires` is typed as AdminPermissionKey, so a typo or a renamed permission
 * is a compile error rather than an action that silently never appears.
 */

export interface PaletteAction {
    id: string
    label: string
    /** Groups the action in the palette and adds searchable context. */
    group: string
    /** Extra terms the fuzzy matcher should consider. */
    keywords?: string
    /** Hash route to navigate to, for navigation actions. */
    href?: string
    /** Imperative handler, for actions that do something. */
    run?: () => void
    /**
     * Permission required to see this at all. Omitted only for actions
     * available to anyone who can open the admin UI.
     */
    requires?: AdminPermissionKey
    /**
     * Mirrors ADMIN_PERMISSIONS' own `dangerous` flag and is set on actions
     * that destroy or grant. Dangerous actions are visually marked and, when
     * invoked from the palette, routed through a typed-name confirmation.
     */
    dangerous?: boolean
}

/**
 * Navigation actions. These mirror the admin routing map rather than inventing
 * destinations, so the palette cannot drift from the sidebar.
 */
export const NAVIGATION_ACTIONS: PaletteAction[] = [
    {
        id: 'nav.sessions',
        label: 'Sessions',
        group: 'Go to',
        keywords: 'active connections live',
        href: '#/status/sessions',
        requires: 'sessionsView',
    },
    {
        id: 'nav.requests',
        label: 'Requests',
        group: 'Go to',
        keywords: 'approvals awaiting action',
        href: '#/status/requests',
        requires: 'approveSessions',
    },
    {
        id: 'nav.login-protection',
        label: 'Login protection',
        group: 'Go to',
        keywords: 'blocked ips locked users fail2ban brute force',
        href: '#/status/login-protection',
        requires: 'configEdit',
    },
    {
        id: 'nav.network',
        label: 'Network status',
        group: 'Go to',
        keywords: 'listeners certificates client ip',
        href: '#/status/network',
        requires: 'configEdit',
    },
    {
        id: 'nav.log',
        label: 'Audit log',
        group: 'Go to',
        keywords: 'events history trail',
        href: '#/log',
        requires: 'sessionsView',
    },
    {
        id: 'nav.targets',
        label: 'Targets',
        group: 'Go to',
        keywords: 'hosts destinations',
        href: '#/config/targets',
        requires: 'targetsEdit',
    },
    {
        id: 'nav.target-groups',
        label: 'Target groups',
        group: 'Go to',
        href: '#/config/target-groups',
        requires: 'targetsEdit',
    },
    {
        id: 'nav.users',
        label: 'Users',
        group: 'Go to',
        keywords: 'accounts people',
        href: '#/config/users',
        requires: 'usersEdit',
    },
    {
        id: 'nav.access-roles',
        label: 'Access roles',
        group: 'Go to',
        href: '#/config/access-roles',
        requires: 'accessRolesEdit',
    },
    {
        id: 'nav.admin-roles',
        label: 'Admin roles',
        group: 'Go to',
        href: '#/config/admin-roles',
        requires: 'adminRolesManage',
        dangerous: true,
    },
    {
        id: 'nav.tickets',
        label: 'Tickets',
        group: 'Go to',
        keywords: 'access credentials temporary',
        href: '#/config/tickets',
        requires: 'ticketsCreate',
    },
    {
        id: 'nav.ssh',
        label: 'SSH keys',
        group: 'Go to',
        keywords: 'known hosts fingerprints own keys',
        href: '#/config/ssh',
        requires: 'configEdit',
    },
    {
        id: 'nav.policies',
        label: 'Policies',
        group: 'Go to',
        keywords: 'auth authentication',
        href: '#/config/policies',
        requires: 'configEdit',
    },
    {
        id: 'nav.ldap',
        label: 'LDAP servers',
        group: 'Go to',
        keywords: 'directory active directory',
        href: '#/config/ldap-servers',
        requires: 'configEdit',
    },
    {
        id: 'nav.parameters',
        label: 'Global parameters',
        group: 'Go to',
        keywords: 'settings configuration sso oidc recordings',
        href: '#/config/parameters',
        requires: 'configEdit',
    },
]

/** Actions that create something. */
export const CREATE_ACTIONS: PaletteAction[] = [
    {
        id: 'new.target',
        label: 'Add a target',
        group: 'Create',
        keywords: 'new host destination',
        href: '#/config/targets/create',
        requires: 'targetsCreate',
    },
    {
        id: 'new.user',
        label: 'Add a user',
        group: 'Create',
        keywords: 'new account',
        href: '#/config/users/create',
        requires: 'usersCreate',
    },
    {
        id: 'new.access-role',
        label: 'Add an access role',
        group: 'Create',
        href: '#/config/access-roles/create',
        requires: 'accessRolesCreate',
    },
    {
        id: 'new.admin-role',
        label: 'Add an admin role',
        group: 'Create',
        href: '#/config/admin-roles/create',
        requires: 'adminRolesManage',
        dangerous: true,
    },
    {
        id: 'new.ticket',
        label: 'Issue a ticket',
        group: 'Create',
        keywords: 'new access credential',
        href: '#/config/tickets/create',
        requires: 'ticketsCreate',
    },
    {
        id: 'new.target-group',
        label: 'Add a target group',
        group: 'Create',
        href: '#/config/target-groups/create',
        requires: 'targetsEdit',
    },
    {
        id: 'new.ldap',
        label: 'Add an LDAP server',
        group: 'Create',
        href: '#/config/ldap-servers/create',
        requires: 'configEdit',
    },
]

/**
 * Drops every action the operator cannot perform.
 *
 * Filtered rather than disabled, deliberately: a greyed-out "Manage admin
 * roles" is still a disclosure.
 */
export function permittedActions(
    actions: PaletteAction[],
    permissions: AdminPermissions,
): PaletteAction[] {
    return actions.filter(action => {
        if (!action.requires) {
            return true
        }
        return permissions[action.requires] === true
    })
}
