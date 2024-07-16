import { formatDistanceToNow } from 'date-fns'

export function timeAgo(t: Date): string {
    return formatDistanceToNow(t, { addSuffix: true })
}
