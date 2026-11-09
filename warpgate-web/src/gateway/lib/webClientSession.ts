// Mirrors SessionPhase in warpgate-web-clients-common
export type CloseReason =
    | 'approval_rejected'
    | 'approval_timed_out'
    | 'error'
    | 'disconnected'

export type SessionPhase =
    | { phase: 'awaiting_approval' }
    | { phase: 'connecting' }
    | { phase: 'connected' }
    | { phase: 'closed'; reason: CloseReason; message: string | null }

export function closeReasonText(
    phase: Extract<SessionPhase, { phase: 'closed' }>,
): string {
    switch (phase.reason) {
        case 'approval_rejected':
            return 'An administrator did not approve this session.'
        case 'approval_timed_out':
            return 'No administrator approved this session in time.'
        case 'error':
            return phase.message ?? 'Connection failed.'
        case 'disconnected':
            return 'Disconnected.'
        default: {
            const reason: string = phase.reason
            return `Session closed (${reason}).`
        }
    }
}
