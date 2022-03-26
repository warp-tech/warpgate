import moment from 'moment'

export function timeAgo(t: any): string {
    return moment(t).fromNow()
}
