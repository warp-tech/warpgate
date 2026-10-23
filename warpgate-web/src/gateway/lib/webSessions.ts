import { get } from 'svelte/store'
import { push } from 'svelte-spa-router'
import { openTargetsInNewTab } from './store'

const webSshRoute = (targetId: string) => `/web-ssh/start/${targetId}`
const webDesktopRoute = (targetId: string) => `/web-desktop/start/${targetId}`
const absoluteUrl = (route: string) => `/@warpgate#${route}`

function maybeOpenInNewTab(route: string) {
    const absolute = absoluteUrl(route)
    if (get(openTargetsInNewTab)) {
        window.open(absolute, '_blank')
    } else if (location.pathname === '/@warpgate') {
        push(route)
    } else {
        location.href = absolute
    }
}

export function webSshUrl(targetId: string): string {
    return absoluteUrl(webSshRoute(targetId))
}

export function webDesktopUrl(targetId: string): string {
    return absoluteUrl(webDesktopRoute(targetId))
}

export function openWebSshSession(targetId: string): void {
    maybeOpenInNewTab(webSshRoute(targetId))
}

export function openWebDesktopSession(targetId: string): void {
    maybeOpenInNewTab(webDesktopRoute(targetId))
}
