import { mount } from 'svelte'
import { api } from 'gateway/lib/api'
import EmbeddedUI from './EmbeddedUI.svelte'

// When proxying a non-secure HTTP target through Warpgate, if
// its internal JS tries to establish a WebSocket connection
// to a ws:// URI, it will fail due to browser restrictions
// So we patch WebSocket to rewrite URIs to wss://
function forceSecureWebSocketURLs() {
    const OriginalWebSocket = window.WebSocket

    function makeUrlSecure(url: string | URL): string | URL {
        if (url instanceof URL) {
            if (url.protocol === 'ws:') {
                url.protocol = 'wss:'
                return url
            }
        } else {
            if (url.startsWith('ws://')) {
                return `wss://${url.slice('ws://'.length)}`
            }
        }
        return url
    }

    // noVNC probes the channel's immediate prototype
    // and a subclass would hide those (#2254)
    window.WebSocket = new Proxy(OriginalWebSocket, {
        construct(target, [url, protocols]) {
            return new target(makeUrlSecure(url), protocols)
        },
    })
}

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

setTimeout(
    () =>
        mount(EmbeddedUI, {
            target: container,
        }),
)

forceSecureWebSocketURLs()
