import { get } from 'svelte/store'
import { push } from 'svelte-spa-router'
import { openTargetsInNewTab } from './store'

function maybeOpenInNewTab(url: string) {
    const absolute = `/@warpgate#${url}`
    if (get(openTargetsInNewTab)) {
        window.open(absolute, '_blank')
    } else if (location.pathname === '/@warpgate') {
        push(url)
    } else {
        location.href = absolute
    }
}

export function openWebSshSession(targetId: string): void {
    maybeOpenInNewTab(`/web-ssh/start/${targetId}`)
}

export function openWebDesktopSession(targetId: string): void {
    maybeOpenInNewTab(`/web-desktop/start/${targetId}`)
}
