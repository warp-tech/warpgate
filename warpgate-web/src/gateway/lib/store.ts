import { writable } from 'svelte/store'
import { api, Info } from './api'

export const serverInfo = writable<Info|null>(null)

export async function reloadServerInfo (): Promise<void> {
    serverInfo.set(await api.getInfo())
}
