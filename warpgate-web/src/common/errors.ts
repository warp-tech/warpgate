import * as admin from 'admin/lib/api'
import * as gw from 'gateway/lib/api'

// eslint-disable-next-line @typescript-eslint/explicit-module-boundary-types
export async function stringifyError (err: any): Promise<string> {
    if (err instanceof gw.ResponseError) {
        return gw.stringifyError(err)
    }
    if (err instanceof admin.ResponseError) {
        return admin.stringifyError(err)
    }
    return err.toString()
}
