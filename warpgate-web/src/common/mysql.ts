import type { Info } from 'gateway/lib/api'

export function makeMySQLUsername (targetName?: string, username?: string): string {
    return `${username ?? 'username'}#${targetName ?? 'target'}`
}

export function makeExampleMySQLCommand (targetName?: string, username?: string, serverInfo?: Info): string {
    return `mysql -u ${makeMySQLUsername(targetName, username)} --host ${serverInfo?.externalHost ?? 'warpgate-host'} --port ${serverInfo?.ports.mysql ?? 'warpgate-mysql-port'} -p --ssl`
}

export function makeExampleMySQLURI (targetName?: string, username?: string, serverInfo?: Info): string {
    return `mysql://${makeMySQLUsername(targetName, username)}:<password>@${serverInfo?.externalHost ?? 'warpgate-host'}:${serverInfo?.ports.mysql ?? 'warpgate-mysql-port'}?sslMode=required`
}
