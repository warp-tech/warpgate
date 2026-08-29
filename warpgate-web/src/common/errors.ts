import * as admin from 'admin/lib/api'
import * as gw from 'gateway/lib/api'

/// The status an API error carried, for callers that can say something better
/// than the response body about a particular one.
export function errorStatus(err: unknown): number | undefined {
    return (err as { response?: Response } | undefined)?.response?.status
}

export async function stringifyError(err: unknown): Promise<string> {
    if (err instanceof gw.ResponseError) {
        return gw.stringifyError(err)
    }
    if (err instanceof admin.ResponseError) {
        return admin.stringifyError(err)
    }
    // A message thrown deliberately is already written for the reader; the
    // `Error:` prefix `String()` adds is noise.
    if (err instanceof Error) {
        return err.message
    }
    return String(err)
}
