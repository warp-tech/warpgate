import { api } from 'gateway/lib/api'
import EmbeddedUI from './EmbeddedUI.svelte'

export { }

navigator.serviceWorker.getRegistrations().then(registrations => {
    for (const registration of registrations) {
        registration.unregister()
    }
})

api.getInfo().then(info => {
    console.log(`Warpgate v${info.version}, logged in as ${info.username}`)
})

const container = document.createElement('div')
container.id = 'warpgate-embedded-ui'
document.body.appendChild(container)

setTimeout(() => new EmbeddedUI({
    target: container,
}))
