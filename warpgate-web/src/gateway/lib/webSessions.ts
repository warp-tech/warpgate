import { handleReauthError } from 'common/reauth'
import { api } from './api'
import { push } from 'svelte-spa-router'
import { get } from 'svelte/store'
import { openTargetsInNewTab } from './store'

function maybeOpenInNewTab(url: string) {
    if (get(openTargetsInNewTab)) {
        window.open(`/@warpgate#${url}`, '_blank')
    } else {
        push(url)
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

export async function openWebDesktopSession(targetId: string): Promise<void> {
    try {
        const { sessionId } = await api.createWebDesktopSession({
            createWebDesktopSessionBody: { targetId },
        })
        maybeOpenInNewTab(`/web-desktop/${sessionId}`)
    } catch (err) {
        if (!(await handleReauthError(err))) {
            throw err
        }
    }
}
