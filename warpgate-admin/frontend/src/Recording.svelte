<script lang="ts">
import { api, Recording } from 'lib/api'
import { Alert, Spinner } from 'sveltestrap'
import * as AsciinemaPlayer from 'asciinema-player'

export let params = { id: '' }

let error: Error|null = null
let recording: Recording|null = null
let playerContainer: HTMLDivElement

async function load () {
    recording = await api.getRecording(params)
    AsciinemaPlayer.create(`/cast/${params.id}`, playerContainer)
}

load().catch(e => {
    error = e
})

</script>

{#if recording}
<h1>{recording.id}</h1>
{/if}

{#if !recording && !error}
<Spinner />
{/if}

{#if error}
<Alert color="danger">{error.message}</Alert>
{/if}

<div bind:this={playerContainer}></div>

<style lang="scss">
    @import "asciinema-player/dist/bundle/asciinema-player.css";
</style>
