import { api } from 'gateway/lib/api'

navigator.serviceWorker.getRegistrations().then(registrations => {
    for (const registration of registrations) {
        registration.unregister()
    }
})

api.getInfo().then(info => {
    console.log(`Warpgate v${info.version}, logged in as ${info.username}`)
})

// eslint-disable-next-line @typescript-eslint/no-useless-empty-export
export { }
