import { serverInfo } from 'gateway/lib/store'
import { get } from 'svelte/store'
import { type AdminRole, api } from './api'

// An action in the admin UI that can take away someone's ability to manage
// admin roles.
export type AdminAccessChange =
    | { kind: 'revokeRole'; userId: string; roleId: string }
    | { kind: 'deleteUser'; userId: string }
    // `role` as it is about to be saved
    | { kind: 'updateRole'; role: AdminRole }
    | { kind: 'deleteRole'; roleId: string }

// Usernames of everyone who can manage admin roles, now and once `change` is
// applied.
async function adminRoleManagers(
    change: AdminAccessChange,
): Promise<{ before: Set<string>; after: Set<string> }> {
    const before = new Set<string>()
    const after = new Set<string>()
    for (const role of await api.getAdminRoles()) {
        const managesAfter =
            change.kind === 'updateRole' && change.role.id === role.id
                ? change.role.adminRolesManage
                : role.adminRolesManage &&
                  !(change.kind === 'deleteRole' && change.roleId === role.id)
        if (!role.adminRolesManage && !managesAfter) {
            continue
        }
        for (const user of await api.getAdminRoleUsers({ id: role.id })) {
            if (role.adminRolesManage) {
                before.add(user.username)
            }
            const loses =
                (change.kind === 'deleteUser' && change.userId === user.id) ||
                (change.kind === 'revokeRole' &&
                    change.userId === user.id &&
                    change.roleId === role.id)
            if (managesAfter && !loses) {
                after.add(user.username)
            }
        }
    }
    return { before, after }
}

// Whoever can manage admin roles can grant any of them, to themselves too, so
// as long as one such user is left, admin access can be fixed from here. With
// nobody left, it can only be restored on the server. Returns a warning to put
// in front of the admin before `change`, or null if there is nothing to warn
// about.
export async function adminAccessWarning(
    change: AdminAccessChange,
): Promise<string | null> {
    let managers: { before: Set<string>; after: Set<string> }
    try {
        managers = await adminRoleManagers(change)
    } catch {
        // A warning only: if it can't be worked out, don't stand in the way.
        return null
    }
    const { before, after } = managers
    if (before.size > 0 && after.size === 0) {
        return (
            'After this, no user will be able to manage admin roles. ' +
            'Admin access can then only be restored on the server, e.g. with ' +
            '`warpgate create-user <username> --role warpgate:admin`.'
        )
    }
    const me = get(serverInfo)?.username
    if (me && before.has(me) && !after.has(me)) {
        return 'You will no longer be able to manage admin roles yourself.'
    }
    return null
}

// `confirm()` for `question`, with the warning, if there is one, in front of it.
export function confirmWithWarning(
    question: string,
    warning: string | null,
): boolean {
    return confirm(warning ? `${warning}\n\n${question}` : question)
}
