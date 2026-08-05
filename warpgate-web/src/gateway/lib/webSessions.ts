import { handleReauthError } from 'common/reauth'
import { get } from 'svelte/store'
import { push } from 'svelte-spa-router'
import { api } from './api'
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

export async function openWebSshSession(targetId: string): Promise<void> {
    try {
        const { sessionId } = await api.createWebSshSession({
            createWebSshSessionBody: { targetId },
        })
        maybeOpenInNewTab(`/web-ssh/${sessionId}`)
    } catch (err) {
        if (!(await handleReauthError(err))) {
            throw err
        }
    }
}

export function openWebDesktopSession(targetId: string): void {
    maybeOpenInNewTab(`/web-desktop/start/${targetId}`)
}
