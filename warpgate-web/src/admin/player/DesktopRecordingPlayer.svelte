<script lang="ts">
    import Fa from 'svelte-fa'
    import { onDestroy, onMount } from 'svelte'
    import { faPlay, faPause, faExpand } from '@fortawesome/free-solid-svg-icons'
    import { Spinner } from '@sveltestrap/sveltestrap'
    import formatDuration from 'format-duration'
    import type { Recording } from 'admin/lib/api'
    import { applyDesktopFrame, type DesktopFrame } from 'common/desktopCanvas'

    export let recording: Recording

    // A recording item is a framebuffer message plus a relative timestamp.
    type RecordingItem = DesktopFrame & { time: number }

    let rootElement: HTMLDivElement
    let canvas: HTMLCanvasElement
    let ctx: CanvasRenderingContext2D | null = null

    let events: RecordingItem[] = []
    let appliedIndex = 0
    let timestamp = 0
    let duration = 0
    let seekInputValue = 0
    let playing = false
    let loading = true
    let sessionIsLive: boolean | null = null
    let socket: WebSocket | null = null
    let destroyed = false

    $: isStreaming = timestamp >= duration && playing

    onDestroy(() => {
        destroyed = true
        socket?.close()
    })

    onMount(async () => {
        if (recording.kind !== 'Desktop') {
            throw new Error('Invalid recording type')
        }
        ctx = canvas.getContext('2d')

        const data = await fetch(`/@warpgate/admin/api/recordings/${recording.id}/desktop`)
            .then(r => r.text())
        for (const line of data.split('\n')) {
            if (line.trim()) {
                addItem(JSON.parse(line) as RecordingItem)
            }
        }

        seek(0)

        socket = new WebSocket(`wss://${location.host}/@warpgate/admin/api/recordings/${recording.id}/desktop-stream`)
        socket.addEventListener('message', event => {
            const message = JSON.parse(event.data)
            if ('data' in message) {
                addItem(message.data as RecordingItem)
            } else if ('start' in message) {
                sessionIsLive = message.live
                if (sessionIsLive) {
                    playing = true
                    seek(duration)
                }
            } else if ('end' in message) {
                sessionIsLive = false
            }
        })
        socket.addEventListener('close', () => console.info('Live stream closed'))

        loading = false
        step()
    })

    function addItem (item: RecordingItem) {
        events.push(item)
        duration = Math.max(duration, item.time)
        if (isStreaming && ctx) {
            applyDesktopFrame(canvas, ctx, item)
            appliedIndex = events.length
            timestamp = item.time
            seekInputValue = duration ? 100 * timestamp / duration : 0
        }
    }

    function seek (time: number) {
        if (!ctx) {
            return
        }
        // Seeking backwards: clear and replay from the start (no keyframe index).
        if (time < timestamp) {
            ctx.clearRect(0, 0, canvas.width, canvas.height)
            appliedIndex = 0
        }
        while (appliedIndex < events.length && events[appliedIndex]!.time <= time) {
            applyDesktopFrame(canvas, ctx, events[appliedIndex]!)
            appliedIndex++
        }
        timestamp = time
        seekInputValue = duration ? 100 * time / duration : 0
    }

    function step () {
        if (destroyed) {
            return
        }
        if (playing) {
            seek(Math.min(duration, timestamp + 0.1))
        }
        setTimeout(step, 100)
    }

    function togglePlaying () {
        playing = !playing
    }

    function toggleFullscreen () {
        if (document.fullscreenElement) {
            document.exitFullscreen()
        } else {
            rootElement.requestFullscreen()
        }
    }
</script>

<div class="root" bind:this={rootElement}>
    {#if loading}
        <Spinner color="primary" />
    {/if}

    <div class="container" class:invisible={loading}>
        <!-- svelte-ignore a11y-no-interactive-element-to-noninteractive-role -->
        <canvas bind:this={canvas} on:click={togglePlaying} role="img"></canvas>
    </div>

    <div class="toolbar" class:invisible={loading}>
        <button class="btn btn-link" on:click={togglePlaying}>
            <Fa icon={playing ? faPause : faPlay} fw />
        </button>
        <pre class="timestamp">{ formatDuration(timestamp * 1000, { leading: true }) }</pre>
        {#if sessionIsLive === true}
            <button
                class="btn live-btn"
                class:active={isStreaming}
                on:click={() => seek(duration)}
            >LIVE</button>
        {/if}
        <input
            class="w-100"
            type="range"
            min="0" max="100" step="0.001"
            style="background-size: {seekInputValue}% 100%;"
            bind:value={seekInputValue}
            on:input={() => seek(duration * seekInputValue / 100)} />
        <button class="btn btn-link" on:click={toggleFullscreen}>
            <Fa icon={faExpand} fw />
        </button>
    </div>
</div>

<style lang="scss">
    .root {
        border-radius: 5px;
        overflow: hidden;
        position: relative;
        contain: content;
        display: flex;
        flex-direction: column;
        background: #262626;
    }

    .container {
        margin: auto;
        max-width: 100%;
        overflow: auto;
    }

    canvas {
        display: block;
        max-width: 100%;
        image-rendering: pixelated;
        cursor: pointer;
    }

    .toolbar {
        display: flex;
    }

    .btn {
        color: #eee;

        :global(svg) {
            transition: all .25s ease-out;
            &:hover {
                transform: scale(1.2);
            }
        }
    }

    :global(.spinner-border) {
        position: absolute;
        left: 50%;
        top: 50%;
        margin: -12px 0 0 -12px;
        z-index: 1;
    }

    input[type="range"] {
        appearance: none;
        -webkit-appearance: none;
        margin: 18px 10px 0;
        height: 2px;
        border-radius: 5px;
        background: linear-gradient(#eee, #eee);
        background-repeat: no-repeat;
        cursor: pointer;
    }

    input[type="range"]::-webkit-slider-thumb {
        -webkit-appearance: none;
        height: 10px;
        width: 10px;
        border-radius: 50%;
        background: #eee;
    }

    .timestamp {
        flex: none;
        overflow: visible;
        color: #eeeeee;
        margin: 0;
        font-size: 0.75rem;
        align-self: center;
    }

    .live-btn {
        font-size: 0.75rem;
        align-self: center;
        color: red;
        flex: none;

        &.active {
            background: red;
            color: white;
            padding: 0.1rem 0.25rem;
            margin: 0 0.5rem;
        }
    }
</style>
