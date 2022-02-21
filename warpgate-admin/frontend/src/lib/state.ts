import { writable } from 'svelte/store'
import { api } from './api'

export const sessions = writable<any[]|null>(null)

export async function reloadSessions (): Promise<void> {
    sessions.set(await api.apiGetAllSessions())
}
