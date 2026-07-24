import { autosave } from 'common/autosave'
import { writable } from 'svelte/store'
import { api, type Info } from './api'

export const serverInfo = writable<Info | undefined>(undefined)

// User preference: when enabled, clicking an HTTP target opens it in a new
// browser tab instead of navigating the current one (which loses the target
// list). Opt-in, off by default, persisted in localStorage.
export const [openHttpInNewTab] = autosave('openHttpInNewTab', false)

export async function reloadServerInfo(): Promise<void> {
    serverInfo.set(await api.getInfo())
}
