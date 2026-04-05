<script lang="ts">
import LogViewer from './log-viewer/LogViewer.svelte'
import { Input } from '@sveltestrap/sveltestrap'
import { autosave } from 'common/autosave'

interface Props {
    params?: {
        id?: string,
    }
    filterKind?: FilterKind,
}

let { params, filterKind = undefined }: Props = $props()

let [target] = autosave<'all' | 'audit'>('log.target', 'all')

function toggleTarget () {
    $target = $target === 'audit' ? 'all' : 'audit'
}

type FilterKind = 'user' | 'access-role' | 'admin-role'


let filters = $derived({
    target: filterKind ? 'audit' : ($target === 'audit' ? 'audit' : undefined),
    relatedUsers: filterKind === 'user' ? params?.id : undefined,
    relatedAccessRoles: filterKind === 'access-role' ? params?.id : undefined,
    relatedAdminRoles: filterKind === 'admin-role' ? params?.id : undefined,
})
</script>

<div class="page-summary-bar d-flex align-items-center justify-content-between">
    <h1>
    {#if filterKind === 'user'}
        user audit log: UID <code>{params?.id}</code>
    {:else if filterKind === 'access-role'}
        access role audit log: ID <code>{params?.id}</code>
    {:else if filterKind === 'admin-role'}
        admin role audit log: ID <code>{params?.id}</code>
    {:else}
        log
    {/if}
    </h1>
    <div class="d-flex align-items-center gap-3">
        {#if !filterKind}
            <Input
                type="switch"
                id="auditOnlyToggle"
                label="Audit log only"
                checked={$target === 'audit'}
                on:change={toggleTarget}
            />
        {/if}
    </div>
</div>

{#key `${$target}-${filterKind}-${params?.id}`}
    <LogViewer filters={filters} />
{/key}
