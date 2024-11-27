<script lang="ts">
import { api, type Recording } from 'admin/lib/api'
import TerminalRecordingPlayer from 'admin/player/TerminalRecordingPlayer.svelte'
import Alert from 'common/sveltestrap-s5-ports/Alert.svelte'
import DelayedSpinner from 'common/DelayedSpinner.svelte'
import { stringifyError } from 'common/errors'

interface Props {
    params: { id: string }
}

let { params = { id: '' } }: Props = $props()

let error: string|null = $state(null)
let recording: Recording|null = $state(null)

async function load () {
    recording = await api.getRecording(params)
}

function getTCPDumpURL () {
    return `/@warpgate/api/recordings/${recording?.id}/tcpdump`
}

load().catch(async e => {
    error = await stringifyError(e)
})

</script>


<div class="page-summary-bar">
    <h1>session recording</h1>
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
