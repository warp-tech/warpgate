import type { Info } from 'gateway/lib/api'

function isLocalhost(hostname: string): boolean {
    return hostname === 'localhost' || hostname.startsWith('127.')
}

/**
 * undefined if no origin switch needed
 */
export function controlPlaneOriginForRedirect(
    info: Info | undefined,
): string | undefined {
    const host = info?.controlPlaneHost
    if (
        !info ||
        !host ||
        host.toLowerCase() === location.hostname.toLowerCase() ||
        isLocalhost(location.hostname)
    ) {
        return undefined
    }
    return `https://${host}:${info.ports.http ?? 443}`
}

export function onControlPlane(info: Info | undefined, url: URL): string {
    const origin = controlPlaneOriginForRedirect(info)
    if (!origin || !/^\/[@_]warpgate(\/|$)/.test(url.pathname)) {
        return url.href
    }
    return `${origin}${url.pathname}${url.search}${url.hash}`
}
