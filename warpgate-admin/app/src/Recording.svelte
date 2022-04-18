<script lang="ts">
import { api, Recording, RecordingKind } from 'lib/api'
import { Alert, Spinner } from 'sveltestrap'
import TerminalRecordingPlayer from 'player/TerminalRecordingPlayer.svelte'

export let params = { id: '' }

let error: Error|null = null
let recording: Recording|null = null
let terminalRecordingURL: string|null = null

async function load () {
    recording = await api.getRecording(params)
    if (recording.kind === 'Terminal') {
        terminalRecordingURL = `/api/recordings/${params.id}/cast`
    }
}

function getTCPDumpURL () {
    return `/api/recordings/${recording?.id}/tcpdump`
}

load().catch(e => {
    error = e
})

</script>


<div class="page-summary-bar">
    <h1>Session recording</h1>
</div>

{#if !recording && !error}
<Spinner />
{/if}

{#if error}
<Alert color="danger">{error}</Alert>
{/if}

{#if recording?.kind === 'Traffic'}
    <a href={getTCPDumpURL()}>Download tcpdump file</a>
{/if}
{#if recording?.kind === 'Terminal' && terminalRecordingURL}
    <TerminalRecordingPlayer url={terminalRecordingURL} />
{/if}
