import { autosave } from 'common/autosave'
import { writable } from 'svelte/store'
import { api, type Info } from './api'

export const serverInfo = writable<Info | undefined>(undefined)

export const [openTargetsInNewTab] = autosave('target-list:open-in-new-tab', true)

export async function reloadServerInfo(): Promise<void> {
    serverInfo.set(await api.getInfo())
}
