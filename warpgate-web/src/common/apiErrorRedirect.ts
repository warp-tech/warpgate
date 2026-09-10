const MFA_SETUP_REQUIRED_HEADER = 'x-warpgate-mfa-setup-required'

interface PostContext {
    url: string
    response: Response
}

function is401ExpectedEndpoint(url: string): boolean {
    return /\/api\/(auth|sso)\//.test(url)
}

function redirectTo(hashRoute: string): void {
    window.location.assign(`/@warpgate#${hashRoute}`)
}

export const apiErrorRedirectMiddleware = {
    async post({ url, response }: PostContext): Promise<void> {
        if (response.ok) {
            return
        }
        if (
            response.status === 403 &&
            response.headers.has(MFA_SETUP_REQUIRED_HEADER)
        ) {
            if (!location.hash.startsWith('#/mfa-setup')) {
                redirectTo('/mfa-setup')
            }
            return
        }
        if (
            response.status === 401 &&
            !is401ExpectedEndpoint(url) &&
            !location.hash.startsWith('#/login')
        ) {
            const next = location.pathname + location.hash
            redirectTo(`/login?next=${encodeURIComponent(next)}`)
        }
    },
}
