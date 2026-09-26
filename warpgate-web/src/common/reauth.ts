import { api, ResponseError } from 'gateway/lib/api'

// If `err` is a 401 raised by a re-authentication-gated endpoint, send the tab
// to the gateway login page (keeping the return target and flagging the reason)
// and return true. Otherwise return false so the caller can handle it.
export async function handleReauthError(err: unknown): Promise<boolean> {
    if (err instanceof ResponseError && err.response.status === 401) {
        // If we don't cancel the current AuthState, the server
        // will just go 'yup, you're logged in aight'
        try {
            await api.cancelDefaultAuth()
        } catch (e) {
            if (!(e instanceof ResponseError && e.response.status === 404)) {
                // 404 if default auth state is already cleared
                throw e
            }
        }

        const next = location.pathname + location.hash
        location.assign(
            `/@warpgate#/login?next=${encodeURIComponent(next)}&reauth=1`,
        )
        return true
    }
    return false
}
