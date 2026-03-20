import { faCheck, faClock, faXmark, faHourglass } from '@fortawesome/free-solid-svg-icons'

export function statusIcon (status: string) {
    switch (status) {
        case 'Pending': return faClock
        case 'Approved': return faCheck
        case 'Denied': return faXmark
        case 'Expired': return faHourglass
        default: return faClock
    }
}

export function statusColor (status: string) {
    switch (status) {
        case 'Pending': return 'text-warning'
        case 'Approved': return 'text-success'
        case 'Denied': return 'text-danger'
        case 'Expired': return 'text-muted'
        default: return 'text-muted'
    }
}
