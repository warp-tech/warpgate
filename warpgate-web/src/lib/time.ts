import moment from 'moment'

export function timeAgo (t: Date): string {
    return moment(t).fromNow()
}
