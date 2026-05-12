import { faCheck, faClock, faXmark, type IconDefinition } from '@fortawesome/free-solid-svg-icons'
import { TicketRequestStatus } from 'admin/lib/api'

export function statusIcon (status: TicketRequestStatus): IconDefinition {
    return {
        [TicketRequestStatus.Pending]: faClock,
        [TicketRequestStatus.Approved]: faCheck,
        [TicketRequestStatus.Denied]: faXmark,
    }[status] ?? faClock
}

export function statusColor (status: TicketRequestStatus): string {
    return {
        [TicketRequestStatus.Pending]: 'text-warning',
        [TicketRequestStatus.Approved]: 'text-success',
        [TicketRequestStatus.Denied]: 'text-danger',
    }[status] ?? 'text-muted'
}
