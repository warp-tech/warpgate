import * as admin from 'admin/lib/api'
import * as gw from 'gateway/lib/api'

export async function stringifyError(err: unknown): Promise<string> {
    if (err instanceof gw.ResponseError) {
        return gw.stringifyError(err)
    }
    if (err instanceof admin.ResponseError) {
        return admin.stringifyError(err)
    }
    return String(err)
}
