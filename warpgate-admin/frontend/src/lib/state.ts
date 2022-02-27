import type { SessionSnapshot } from '../../api-client/src'
import { writable } from 'svelte/store'
import { api } from './api'

export const sessions = writable<SessionSnapshot[]|null>(null)

export async function reloadSessions (): Promise<void> {
    sessions.set(await api.apiGetAllSessions())
}
