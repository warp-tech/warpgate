import { derived } from 'svelte/store'
import { serverInfo } from 'gateway/lib/store'
import type { AdminPermissions } from 'gateway/lib/api'

export interface AdminPermissionDef {
    key: string
    label: string
    category?: string
    deps?: string[]
    dangerous?: boolean
}

export const ADMIN_PERMISSIONS = [
    {
        key: 'targetsCreate' as const,
        label: 'Create',
        category: 'Targets' as const,
        deps: ['targetsEdit'],
    },
    {
        key: 'targetsEdit' as const,
        label: 'Edit',
        category: 'Targets' as const,
    },
    {
        key: 'targetsDelete' as const, label: 'Delete',
        category: 'Targets' as const,
        deps: ['targetsCreate', 'targetsEdit'],
    },
    {
        key: 'usersCreate' as const,
        label: 'Create',
        category: 'Users' as const,
        deps: ['usersEdit'],
    },
    {
        key: 'usersEdit' as const,
        label: 'Edit',
        category: 'Users' as const,
    },
    {
        key: 'usersDelete' as const, label: 'Delete',
        category: 'Users' as const,
        deps: ['usersCreate', 'usersEdit'],
    },
    {
        key: 'accessRolesCreate' as const,
        label: 'Create',
        category: 'Access roles' as const,
        deps: ['accessRolesEdit'],
    },
    {
        key: 'accessRolesEdit' as const,
        label: 'Edit',
        category: 'Access roles' as const,
    },
    {
        key: 'accessRolesDelete' as const, label: 'Delete',
        category: 'Access roles' as const,
        deps: ['accessRolesCreate', 'accessRolesEdit'],
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
        key: 'sessionsTerminate' as const, label: 'Terminate',
        category: 'Sessions' as const,
        deps: ['sessionsView'],
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
        key: 'ticketsDelete' as const, label: 'Delete',
        category: 'Tickets' as const,
        deps: ['ticketsCreate'],
    },
    {
        key: 'configEdit' as const,
        label: 'Edit configuration',
        category: 'Configuration' as const,
    },
    {
        key: 'adminRolesManage' as const,
        label: 'Manage admin roles',
        category: 'Configuration', dangerous: true } as const,
]

// eslint-disable-next-line @typescript-eslint/no-type-alias
export type AdminPermission = typeof ADMIN_PERMISSIONS[number]
// eslint-disable-next-line @typescript-eslint/no-type-alias
export type AdminPermissionKey = AdminPermission['key']
// eslint-disable-next-line @typescript-eslint/no-type-alias
export type AdminPermissionCategory = AdminPermission['category']

export function emptyPermissions(): AdminPermissions {
    return ADMIN_PERMISSIONS.reduce(
        (acc, {
            key }) => ({ ...acc,
            [key]: false }),
        {} as unknown as AdminPermissions,
    )
}

export const adminPermissions = derived(serverInfo, $serverInfo => {
    return $serverInfo?.adminPermissions ?? emptyPermissions()
})

export const hasAdminAccess = derived(adminPermissions, $adminPermissions => {
    return Object.values($adminPermissions).some(v => v)
})
