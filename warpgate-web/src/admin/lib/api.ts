import { DefaultApi, Configuration } from './api-client/dist'

const configuration = new Configuration({
    basePath: '/@warpgate/admin/api',
})

export const api = new DefaultApi(configuration)
export * from './api-client'
