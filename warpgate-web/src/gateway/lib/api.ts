import { DefaultApi, Configuration } from './api-client'

const configuration = new Configuration({
    basePath: '/@warpgate/api',
})

export const api = new DefaultApi(configuration)
export * from './api-client'
