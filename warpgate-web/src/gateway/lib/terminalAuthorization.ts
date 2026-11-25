/**
 * Hand-off protocol for `#/authorize-terminal?app=…&redirect_uri=…&state=…`,
 * which lets a desktop client (e.g. Tabby) obtain an API token and register
 * its SSH key in one click.
 *
 * The client listens on `http://127.0.0.1:<port>/…` (`redirect_uri`) and
 * must answer CORS preflights from the Warpgate origin, including
 * `Access-Control-Allow-Private-Network: true`. The page then POSTs JSON:
 * - probe:  `{ type: 'probe', state }` → `{ public_key? }`. The key comes
 *   from the live client rather than the link, so a crafted link can't plant
 *   someone else's key.
 * - result: `{ type: 'result', state, token, token_id, public_key_id? }`
 *   or `{ type: 'result', state, error: 'denied' }`.
 * Nothing goes through the URL, so the token never lands in browser history.
 */

export type TerminalAuthorizationResult =
    | { token: string; token_id: string; public_key_id?: string }
    | { error: 'denied' }

/**
 * Only the IPv4 loopback literal (RFC 8252 §7.3): anything else would let a
 * crafted link ship the user's new token elsewhere, and it is what the
 * gateway CSP allows in `connect-src`.
 */
export function parseLoopbackRedirectUri(raw: string | null): URL {
    let url: URL
    try {
        url = new URL(raw ?? '')
    } catch {
        throw new Error('The request has no valid redirect address.')
    }
    if (
        url.protocol !== 'http:' ||
        url.hostname !== '127.0.0.1' ||
        url.username ||
        url.password
    ) {
        throw new Error(
            'The redirect address must point to this computer (http://127.0.0.1).',
        )
    }
    return url
}

/** `SHA256:…` fingerprint as printed by `ssh-keygen -l`. */
export async function sshKeyFingerprint(
    opensshPublicKey: string,
): Promise<string> {
    const [, blob] = opensshPublicKey.trim().split(/\s+/)
    if (!blob) {
        throw new Error('The SSH public key is malformed.')
    }
    let bytes: Uint8Array<ArrayBuffer>
    try {
        bytes = Uint8Array.from(atob(blob), c => c.charCodeAt(0))
    } catch {
        throw new Error('The SSH public key is malformed.')
    }
    const digest = await crypto.subtle.digest('SHA-256', bytes)
    const b64 = btoa(String.fromCharCode(...new Uint8Array(digest)))
    return `SHA256:${b64.replace(/=+$/, '')}`
}

async function post(url: URL, body: object): Promise<unknown> {
    const response = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
    })
    if (!response.ok) {
        throw new Error(`The client answered ${response.status}`)
    }
    return response.json().catch(() => ({}))
}

/** The client's SSH key, or throws if no client answered on this machine. */
export async function probeClient(
    url: URL,
    state: string,
): Promise<{ publicKey?: string }> {
    let body: unknown
    try {
        body = await post(url, { type: 'probe', state })
    } catch {
        throw new Error(
            'The application could not be reached on this computer. Make sure it is still waiting, and allow access to local network devices if the browser asks.',
        )
    }
    const key = (body as { public_key?: unknown } | null)?.public_key
    return { publicKey: typeof key === 'string' ? key.trim() : undefined }
}

export async function deliverResult(
    url: URL,
    state: string,
    result: TerminalAuthorizationResult,
): Promise<void> {
    await post(url, { type: 'result', state, ...result })
}
