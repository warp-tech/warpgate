import {
    api,
    type SessionApprovalItem,
    type TicketRequest,
    TicketRequestStatus,
} from 'admin/lib/api'

export const APPROVAL_POLL_INTERVAL_MS = 30000

/** Each kind of request has its own permission, so an admin only ever sees what
 * they are allowed to act on. */
export interface ApprovalRequestPermissions {
    canSeeSessions: boolean
    canManageTickets: boolean
}

export interface PendingRequests {
    sessions: SessionApprovalItem[]
    tickets: TicketRequest[]
}

export async function loadPendingRequests(
    permissions: ApprovalRequestPermissions,
): Promise<PendingRequests> {
    const [sessions, tickets] = await Promise.all([
        permissions.canSeeSessions
            ? api.getSessionApprovals()
            : Promise.resolve([]),
        permissions.canManageTickets
            ? api.getTicketRequests({ status: TicketRequestStatus.Pending })
            : Promise.resolve([]),
    ])
    return { sessions, tickets }
}

/**
 * Calls `onChange` whenever the pending set may have changed, until the
 * returned cleanup runs.
 *
 * The socket only makes updates arrive *sooner*; the interval is what makes the
 * view converge, and it runs regardless of which permissions are held. It
 * covers ticket requests (never pushed), sessions held on another cluster node
 * (the push signal is node-local), requests resolved by another admin, and a
 * socket that died without saying so — which is also why a dead socket needs no
 * reconnect logic.
 */
export function watchPendingRequests(
    permissions: ApprovalRequestPermissions,
    onChange: () => void,
): () => void {
    if (!permissions.canSeeSessions && !permissions.canManageTickets) {
        return () => {}
    }

    onChange()
    const interval = setInterval(onChange, APPROVAL_POLL_INTERVAL_MS)

    let socket: WebSocket | undefined
    if (permissions.canSeeSessions) {
        socket = new WebSocket(
            `wss://${location.host}/@warpgate/admin/api/session-approvals/changes`,
        )
        socket.addEventListener('message', onChange)
    }

    return () => {
        socket?.close()
        clearInterval(interval)
    }
}
