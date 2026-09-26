import { apiErrorRedirectMiddleware } from 'common/apiErrorRedirect'
import {
    Configuration,
    DefaultApi,
    type ResponseError,
} from './api-client/dist'

const configuration = new Configuration({
    basePath: '/@warpgate/admin/api',
    middleware: [apiErrorRedirectMiddleware],
})

export const api = new DefaultApi(configuration)
export * from './api-client'

export async function stringifyError(err: ResponseError): Promise<string> {
    // Not every failure carries a body — a bare 404 is the common one — and
    // "API error:" followed by nothing tells the reader less than the status.
    const body = await err.response.text()
    return `API error: ${body || `${err.response.status} ${err.response.statusText}`}`
}
