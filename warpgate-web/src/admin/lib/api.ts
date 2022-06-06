import { DefaultApi, Configuration } from '../../../api-client/dist'

const configuration = new Configuration({
    basePath: '/api',
})

export const api = new DefaultApi(configuration)
export * from '../../../api-client'
