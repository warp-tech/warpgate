<script lang="ts">
import { api, Recording } from 'admin/lib/api'
import { Alert } from '@sveltestrap/sveltestrap'
import TerminalRecordingPlayer from 'admin/player/TerminalRecordingPlayer.svelte'
import DelayedSpinner from 'common/DelayedSpinner.svelte'

export let params = { id: '' }

let error: Error|null = null
let recording: Recording|null = null

async function load () {
    recording = await api.getRecording(params)
}

function getTCPDumpURL () {
    return `/@warpgate/api/recordings/${recording?.id}/tcpdump`
}

load().catch(e => {
    error = e
})

</script>


<div class="page-summary-bar">
    <h1>Session recording</h1>
</div>

{#if !recording && !error}
    <DelayedSpinner />
{/if}

{#if error}
<Alert color="danger">{error}</Alert>
{/if}

{#if recording?.kind === 'Traffic'}
    <a href={getTCPDumpURL()}>Download tcpdump file</a>
{/if}
{#if recording?.kind === 'Terminal'}
    <TerminalRecordingPlayer recording={recording} />
{/if}
