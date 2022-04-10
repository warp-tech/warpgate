<script lang="ts">
import { api, Recording, RecordingKind } from 'lib/api'
import { Alert, Spinner } from 'sveltestrap'
import * as AsciinemaPlayer from 'asciinema-player'

export let params = { id: '' }

let error: Error|null = null
let recording: Recording|null = null
let playerContainer: HTMLDivElement

async function load () {
    recording = await api.getRecording(params)
    if (recording.kind === 'Terminal') {
        AsciinemaPlayer.create(`/api/recordings/${params.id}/cast`, playerContainer)
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
<div bind:this={playerContainer}></div>

<style lang="scss">
    @import "asciinema-player/dist/bundle/asciinema-player.css";
</style>
