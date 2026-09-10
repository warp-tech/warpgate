import { router } from 'svelte-spa-router'

/**
 * Query parameters of the current hash route, e.g. `#/foo?a=b`.
 * Read once at component init - svelte-spa-router keeps the component
 * mounted when only the querystring changes.
 */
export function routeQueryParams(): URLSearchParams {
    return new URLSearchParams(router.querystring ?? '')
}

/**
 * Navigate to a URL that originates outside Warpgate - currently the
 * `authorization_endpoint` / `end_session_endpoint` an OIDC provider
 * advertises in its discovery document.
 *
 * Assigning e.g. a `javascript:` URL to `location.href` runs it on our own
 * origin, so only http(s) is allowed through. The backend rejects such
 * endpoints at discovery time; this is the second line of defence.
 */
export function navigateToExternalUrl(url: string): void {
    let parsed: URL
    try {
        parsed = new URL(url, location.href)
    } catch {
        throw new Error(`Refusing to navigate to a malformed URL: ${url}`)
    }
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        throw new Error(`Refusing to navigate to a non-HTTP URL: ${url}`)
    }
    location.href = url
}

export function downloadBlob(content: string, filename: string): void {
    const blob = new Blob([content], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
}

type ClassValue =
    | string
    | number
    | boolean
    | null
    | undefined
    | ClassValue[]
    | Record<string, unknown>

export function toClassName(value: ClassValue): string {
    let result = ''

    if (typeof value === 'string' || typeof value === 'number') {
        result += value
    } else if (typeof value === 'object' && value !== null) {
        if (Array.isArray(value)) {
            result = value.map(toClassName).filter(Boolean).join(' ')
        } else {
            for (const key in value) {
                if (value[key]) {
                    if (result) {
                        result += ' '
                    }
                    result += key
                }
            }
        }
    }

    return result
}

export const classnames = (...args: ClassValue[]): string =>
    args.map(toClassName).filter(Boolean).join(' ')

export function uuid(): string {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
        const r = (Math.random() * 16) | 0
        const v = c === 'x' ? r : (r & 0x3) | 0x8
        return v.toString(16)
    })
}
