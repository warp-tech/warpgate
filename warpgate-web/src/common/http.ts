import type { Info } from 'gateway/lib/api'

export function makeTargetURL (targetName: string, targetExternalHost?: string, serverInfo?: Info): string {
    const host = targetExternalHost ? `${targetExternalHost}:${serverInfo?.ports.http ?? 443}` : location.host
    return `${location.protocol}//${host}/?warpgate-target=${targetName}`
}
