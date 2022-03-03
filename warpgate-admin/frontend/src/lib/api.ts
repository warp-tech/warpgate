import { DefaultApi, Configuration } from '../../api-client/src'

const configuration = new Configuration({
    basePath: '/api'
})

export const api = new DefaultApi(configuration)
export * from '../../api-client/src/models'
