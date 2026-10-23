import type { Info } from 'gateway/lib/api'

/** The admin UI's address: on this listener, or on the separate admin
 * listener (`http.admin`) when the server reports one. */
export function adminHref(info: Info | undefined, rest = ''): string {
    return (info?.adminUrl ?? '/@warpgate/admin') + rest
}
