/**
 * Hand-off protocol for `#/authorize-terminal?app=…&redirect_uri=…&state=…`,
 * which lets a desktop client (e.g. Tabby) obtain an API token and register
 * its SSH key in one click.
 *
 * The client listens on `http://127.0.0.1:<port>/…` (`redirect_uri`) and
 * must answer CORS preflights from the Warpgate origin, including
 * `Access-Control-Allow-Private-Network: true`. The page then POSTs JSON:
 * - probe:  `{ type: 'probe', state }` → `{ public_key?, public_key_id? }`.
 *   The key comes from the live client rather than the link, so a crafted
 *   link can't plant someone else's key. A client re-authorizing with a key
 *   it registered before sends its id too; if the user still has that key,
 *   it is reused instead of being added again.
 * - result: `{ type: 'result', state, token, token_id, public_key_id? }`
 *   or `{ type: 'result', state, error: 'denied' }`.
 * Nothing goes through the URL, so the token never lands in browser history.
 *
 * Any web page can POST to the client, so it must check `state` on every
 * request; that is what proves the request is genuine. `Origin` is not
 * necessarily the URL the user gave the client: in a cluster, logging in
 * moves the browser to the control plane (`control_plane_host` in `/info`),
 * so accept that origin too.
 *
 * Each request times out after 10 s, and unless the page sees a 2xx to
 * `result` it revokes the token and key again. A reply that got lost leaves
 * the client holding a revoked token, so it should treat a later 401 as
 * "authorize again".
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

const REQUEST_TIMEOUT_MS = 10_000

async function post(url: URL, body: object): Promise<unknown> {
    const response = await fetch(url, {
        method: 'POST',
        redirect: 'error',
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
    })
    if (!response.ok) {
        throw new Error(`The client answered ${response.status}`)
    }
    return response.json().catch(() => ({}))
}

export async function probeClient(
    url: URL,
    state: string,
): Promise<{ publicKey?: string; publicKeyId?: string }> {
    let body: unknown
    try {
        body = await post(url, { type: 'probe', state })
    } catch {
        throw new Error(
            'The application could not be reached on this computer. Make sure it is still waiting, and allow access to local network devices if the browser asks.',
        )
    }
    const { public_key: key, public_key_id: keyId } =
        (body as { public_key?: unknown; public_key_id?: unknown } | null) ?? {}
    return {
        publicKey: typeof key === 'string' ? key.trim() : undefined,
        publicKeyId: typeof keyId === 'string' ? keyId : undefined,
    }
}

export async function deliverResult(
    url: URL,
    state: string,
    result: TerminalAuthorizationResult,
): Promise<void> {
    await post(url, { type: 'result', state, ...result })
}
