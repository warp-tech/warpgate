import { handleReauthError } from 'common/reauth'
import { api } from './api'

export async function openWebSshSession(targetId: string): Promise<void> {
    try {
        const { sessionId } = await api.createWebSshSession({
            createWebSshSessionBody: { targetId },
        })
        window.open(`/@warpgate#/web-ssh/${sessionId}`, '_blank')
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
        window.open(`/@warpgate#/web-desktop/${sessionId}`, '_blank')
    } catch (err) {
        if (!(await handleReauthError(err))) {
            throw err
        }
    }
}
