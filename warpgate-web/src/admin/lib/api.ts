import { DefaultApi, Configuration, ResponseError } from './api-client/dist'

const configuration = new Configuration({
    basePath: '/@warpgate/admin/api',
})

export const api = new DefaultApi(configuration)
export * from './api-client'

export async function stringifyError (err: ResponseError): Promise<string> {
    return `API error: ${await err.response.text()}`
}
