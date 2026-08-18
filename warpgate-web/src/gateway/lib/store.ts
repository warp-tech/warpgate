import { autosave } from 'common/autosave'
import { derived, writable } from 'svelte/store'
import { api, type Info } from './api'

export const serverInfo = writable<Info | undefined>(undefined)

const [openTargetsInNewTabPreference] = autosave<boolean | null>(
    'target-list:open-in-new-tab',
    null,
)

export const [collapsedTargetGroups] = autosave<string[]>(
    'target-list:collapsed-groups',
    [],
)

export const openTargetsInNewTab = derived(
    [openTargetsInNewTabPreference, serverInfo],
    ([$preference, $serverInfo]) => {
        switch ($serverInfo?.openTargetsInNewTab) {
            case 'ForcedOn':
                return true
            case 'ForcedOff':
                return false
            case 'DefaultOff':
                return $preference ?? false
            default:
                return $preference ?? true
        }
    },
)

export const openTargetsInNewTabForced = derived(
    serverInfo,
    $serverInfo =>
        $serverInfo?.openTargetsInNewTab === 'ForcedOn' ||
        $serverInfo?.openTargetsInNewTab === 'ForcedOff',
)

export function setOpenTargetsInNewTab(value: boolean): void {
    openTargetsInNewTabPreference.set(value)
}

export async function reloadServerInfo(): Promise<void> {
    serverInfo.set(await api.getInfo())
}
