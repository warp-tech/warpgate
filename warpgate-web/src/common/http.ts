export function makeTargetURL (targetName: string): string {
    return `${location.protocol}//${location.host}/?warpgate-target=${targetName}`
}
