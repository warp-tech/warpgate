import { shellEscape } from 'gateway/lib/shellEscape'
import type { Info } from 'gateway/lib/api'

export interface ConnectionOptions {
    targetName?: string
    username?: string
    serverInfo?: Info
    targetExternalHost?: string
    ticketSecret?: string
}

export function makeSSHUsername (opt: ConnectionOptions): string {
    if (opt.ticketSecret) {
        return `ticket-${opt.ticketSecret}`
    }
    return `${opt.username ?? 'username'}:${opt.targetName ?? 'target'}`
}

export function makeExampleSSHCommand (opt: ConnectionOptions): string {
    return shellEscape(['ssh', `${makeSSHUsername(opt)}@${opt.serverInfo?.externalHost ?? 'warpgate-host'}`, '-p', (opt.serverInfo?.ports.ssh ?? 'warpgate-ssh-port').toString()])
}

export function makeMySQLUsername (opt: ConnectionOptions): string {
    if (opt.ticketSecret) {
        return `ticket-${opt.ticketSecret}`
    }
    return `${opt.username ?? 'username'}#${opt.targetName ?? 'target'}`
}

export function makeExampleMySQLCommand (opt: ConnectionOptions): string {
    let cmd = shellEscape(['mysql', '-u', makeMySQLUsername(opt), '--host', opt.serverInfo?.externalHost ?? 'warpgate-host', '--port', (opt.serverInfo?.ports.mysql ?? 'warpgate-mysql-port').toString(), '--ssl'])
    if (!opt.ticketSecret) {
        cmd += ' -p'
    }
    return cmd
}

export function makeExampleMySQLURI (opt: ConnectionOptions): string {
    const pwSuffix = opt.ticketSecret ? '' : ':<password>'
    return `mysql://${makeMySQLUsername(opt)}${pwSuffix}@${opt.serverInfo?.externalHost ?? 'warpgate-host'}:${opt.serverInfo?.ports.mysql ?? 'warpgate-mysql-port'}?sslMode=required`
}

export const makePostgreSQLUsername = makeMySQLUsername

export function makeExamplePostgreSQLCommand (opt: ConnectionOptions): string {
    return shellEscape(['psql', '-U', makeMySQLUsername(opt), '--host', opt.serverInfo?.externalHost ?? 'warpgate-host', '--port', (opt.serverInfo?.ports.postgres ?? 'warpgate-postgres-port').toString()])
}

export function makeExamplePostgreSQLURI (opt: ConnectionOptions): string {
    const pwSuffix = opt.ticketSecret ? '' : ':<password>'
    return `postgresql://${makePostgreSQLUsername(opt)}${pwSuffix}@${opt.serverInfo?.externalHost ?? 'warpgate-host'}:${opt.serverInfo?.ports.postgres ?? 'warpgate-postgres-port'}?sslmode=require`
}

export function makeTargetURL (opt: ConnectionOptions): string {
    const host = opt.targetExternalHost ? `${opt.targetExternalHost}:${opt.serverInfo?.ports.http ?? 443}` : location.host
    if (opt.ticketSecret) {
        return `${location.protocol}//${host}/?warpgate-ticket=${opt.ticketSecret}`
    }
    return `${location.protocol}//${host}/?warpgate-target=${opt.targetName}`
}
