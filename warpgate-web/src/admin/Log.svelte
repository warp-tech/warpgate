<script lang="ts">
import LogViewer from './log-viewer/LogViewer.svelte'
import { Input } from '@sveltestrap/sveltestrap'
import { autosave } from 'common/autosave'

let [target] = autosave<'all' | 'audit'>('log.target', 'all')

function toggleTarget () {
    $target = $target === 'audit' ? 'all' : 'audit'
}
</script>

<div class="page-summary-bar d-flex align-items-center justify-content-between">
    <h1>log</h1>
    <Input
        type="switch"
        id="auditOnlyToggle"
        label="Audit log only"
        checked={$target === 'audit'}
        on:change={toggleTarget}
    />
</div>

{#key $target}
<LogViewer filters={{ target: $target === 'audit' ? 'audit' : undefined }} />
{/key}
