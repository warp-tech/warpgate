import { writable } from 'svelte/store'
import { api, SessionSnapshot } from './api'

export const sessions = writable<SessionSnapshot[]|null>(null)

export async function reloadSessions (): Promise<void> {
    sessions.set(await api.getSessions())
}
