import type { AdminPermissions } from 'gateway/lib/api'
import { serverInfo } from 'gateway/lib/store'
import { derived } from 'svelte/store'
import type { AdminRole } from './api'

export type AdminRolePermissionKey = {
    [K in keyof AdminRole]: AdminRole[K] extends boolean ? K : never
}[keyof AdminRole]

export interface AdminPermissionDef {
    key: AdminRolePermissionKey
    label: string
    category?: string
    deps?: AdminRolePermissionKey[]
    dangerous?: boolean
}

export const ADMIN_PERMISSIONS = [
    {
        key: 'targetsCreate' as const,
        label: 'Create',
        category: 'Targets' as const,
        deps: ['targetsEdit'] as AdminRolePermissionKey[],
    },
    {
        key: 'targetsEdit' as const,
        label: 'Edit',
        category: 'Targets' as const,
    },
    {
        key: 'targetsDelete' as const,
        label: 'Delete',
        category: 'Targets' as const,
        deps: ['targetsCreate', 'targetsEdit'] as AdminRolePermissionKey[],
    },
    {
        key: 'usersCreate' as const,
        label: 'Create',
        category: 'Users' as const,
        deps: ['usersEdit'] as AdminRolePermissionKey[],
    },
    {
        key: 'usersEdit' as const,
        label: 'Edit',
        category: 'Users' as const,
    },
    {
        key: 'usersDelete' as const,
        label: 'Delete',
        category: 'Users' as const,
        deps: ['usersCreate', 'usersEdit'] as AdminRolePermissionKey[],
    },
    {
        key: 'accessRolesCreate' as const,
        label: 'Create',
        category: 'Access roles' as const,
        deps: ['accessRolesEdit'] as AdminRolePermissionKey[],
    },
    {
        key: 'accessRolesEdit' as const,
        label: 'Edit',
        category: 'Access roles' as const,
    },
    {
        key: 'accessRolesDelete' as const,
        label: 'Delete',
        category: 'Access roles' as const,
        deps: [
            'accessRolesCreate',
            'accessRolesEdit',
        ] as AdminRolePermissionKey[],
    },
    {
        key: 'accessRolesAssign' as const,
        label: 'Assign',
        category: 'Access roles' as const,
    },
    {
        key: 'sessionsView' as const,
        label: 'View',
        category: 'Sessions' as const,
    },
    {
        key: 'sessionsTerminate' as const,
        label: 'Terminate',
        category: 'Sessions' as const,
        deps: ['sessionsView'] as AdminRolePermissionKey[],
    },
    {
        key: 'approveSessions' as const,
        label: 'Approve',
        category: 'Sessions' as const,
        deps: ['sessionsView'] as AdminRolePermissionKey[],
    },
    {
        key: 'recordingsView' as const,
        label: 'View',
        category: 'Recordings' as const,
    },
    {
        key: 'ticketsCreate' as const,
        label: 'Create',
        category: 'Tickets' as const,
    },
    {
        key: 'ticketsDelete' as const,
        label: 'Delete',
        category: 'Tickets' as const,
        deps: ['ticketsCreate'] as AdminRolePermissionKey[],
    },
    {
        key: 'configEdit' as const,
        label: 'Edit configuration',
        category: 'Configuration' as const,
    },
    {
        key: 'ticketRequestsManage' as const,
        label: 'Manage',
        category: 'Ticket requests' as const,
    },
    {
        key: 'adminRolesManage' as const,
        label: 'Manage admin roles',
        category: 'Configuration',
        dangerous: true,
    } as const,
]

export type AdminPermission = (typeof ADMIN_PERMISSIONS)[number]
export type AdminPermissionKey = AdminPermission['key']
export type AdminPermissionCategory = AdminPermission['category']

export function emptyPermissions(): AdminPermissions {
    return ADMIN_PERMISSIONS.reduce(
        // biome-ignore lint/performance/noAccumulatingSpread: small
        (acc, { key }) => ({ ...acc, [key]: false }),
        {} as unknown as AdminPermissions,
    )
}

export const adminPermissions = derived(serverInfo, $serverInfo => {
    return $serverInfo?.adminPermissions ?? emptyPermissions()
})

export const hasAdminAccess = derived(adminPermissions, $adminPermissions => {
    return Object.values($adminPermissions).some(v => v)
})
