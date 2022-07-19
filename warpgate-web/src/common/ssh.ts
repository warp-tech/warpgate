import type { Info } from 'gateway/lib/api'

export function makeSSHUsername (targetName?: string, username?: string): string {
    return `${username ?? 'username'}:${targetName ?? 'target'}`
}

export function makeExampleSSHCommand (targetName?: string, username?: string, serverInfo?: Info): string {
    return `ssh ${makeSSHUsername(targetName, username)}@${serverInfo?.externalHost ?? 'warpgate-host'} -p ${serverInfo?.ports.ssh ?? 'warpgate-ssh-port'}`
}
