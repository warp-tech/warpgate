import type { Target, UserSnapshot } from './api'

export function getSSHUsername (user: UserSnapshot|undefined, target: Target|undefined): string {
    return `${user?.username ?? "<username>"}:${target?.name}`
}
