<script lang="ts">
    import Fa from 'svelte-fa'
    import { onDestroy, onMount } from 'svelte'
    import { faPlay, faPause, faExpand } from '@fortawesome/free-solid-svg-icons'
    import { Spinner } from '@sveltestrap/sveltestrap'
    import formatDuration from 'format-duration'
    import type { Recording } from 'admin/lib/api'
    import { applyDesktopFrame, type DesktopFrame } from 'common/desktopCanvas'
    import { keysymLabel, scancodeLabel, type KeyPress, type Click } from 'common/desktopInput'

    export let recording: Recording

    // How long a click ring animates / a pressed key stays on the overlay (seconds).
    const CLICK_ANIM_S = 0.6
    const KEY_DISPLAY_S = 3

    // Viewer-input items carry a timestamp too, but aren't framebuffer messages.
    type InputItem =
        | { type: 'key_input', time: number, keysym: number, down: boolean }
        | { type: 'scancode_input', time: number, code: number, extended: boolean, down: boolean }
        | { type: 'pointer_input', time: number, x: number, y: number, buttons: number }
        | { type: 'wheel_input', time: number }
        | { type: 'clipboard_input', time: number }

    // A recording item is a framebuffer message or an input item, plus a timestamp.
    type RecordingItem = (DesktopFrame | InputItem) & { time: number }

    let rootElement: HTMLDivElement
    let canvas: HTMLCanvasElement
    let ctx: CanvasRenderingContext2D | null = null

    let events: RecordingItem[] = []
    let appliedIndex = 0
    let timestamp = 0
    let duration = 0

    // Viewer input, extracted for the live-input overlay. Populated in time order.
    let keyPresses: KeyPress[] = []
    let clicks: Click[] = []
    let prevButtons = 0
    // Intrinsic framebuffer size, for positioning click rings as a % of the canvas.
    let canvasW = 0
    let canvasH = 0

    // Derived purely from `timestamp`, so overlays stay correct across seek/scrub.
    $: activeKeys = keyPresses.filter(k => k.time <= timestamp && k.time > timestamp - KEY_DISPLAY_S)
    $: activeClicks = clicks.filter(c => c.time <= timestamp && c.time > timestamp - CLICK_ANIM_S)
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
        duration = Math.max(duration, item.time)
        // Viewer-input items feed the overlay only; they never touch the framebuffer.
        if (recordInput(item)) {
            if (isStreaming) {
                timestamp = item.time
                seekInputValue = duration ? 100 * timestamp / duration : 0
            }
            return
        }
        events.push(item)
        if (isStreaming && ctx) {
            applyDesktopFrame(canvas, ctx, item as DesktopFrame)
            appliedIndex = events.length
            timestamp = item.time
            canvasW = canvas.width
            canvasH = canvas.height
            seekInputValue = duration ? 100 * timestamp / duration : 0
        }
    }

    // Extract a viewer-input item into the overlay arrays. Returns true if `item` was
    // input (i.e. not a framebuffer message). Clicks are button-press transitions.
    function recordInput (item: RecordingItem): boolean {
        switch (item.type) {
            case 'key_input':
                if (item.down) {
                    keyPresses = [...keyPresses, { time: item.time, label: keysymLabel(item.keysym) }]
                }
                return true
            case 'scancode_input':
                if (item.down) {
                    keyPresses = [...keyPresses, { time: item.time, label: scancodeLabel(item.code) }]
                }
                return true
            case 'pointer_input': {
                const pressed = item.buttons & ~prevButtons
                prevButtons = item.buttons
                if (pressed) {
                    clicks = [...clicks, { time: item.time, x: item.x, y: item.y }]
                }
                return true
            }
            case 'wheel_input':
            case 'clipboard_input':
                return true
        }
        return false
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
            applyDesktopFrame(canvas, ctx, events[appliedIndex]! as DesktopFrame)
            appliedIndex++
        }
        timestamp = time
        canvasW = canvas.width
        canvasH = canvas.height
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
        <div class="stage">
            <!-- svelte-ignore a11y-no-interactive-element-to-noninteractive-role -->
            <canvas bind:this={canvas} on:click={togglePlaying} role="img"></canvas>

            <div class="click-layer">
                {#each activeClicks as click (click)}
                    {@const progress = (timestamp - click.time) / CLICK_ANIM_S}
                    <span
                        class="click-ring"
                        style="left: {canvasW ? 100 * click.x / canvasW : 0}%;
                               top: {canvasH ? 100 * click.y / canvasH : 0}%;
                               transform: translate(-50%, -50%) scale({0.4 + progress});
                               opacity: {1 - progress};"
                    ></span>
                {/each}
            </div>

            {#if activeKeys.length}
                <div class="key-layer">
                    {#each activeKeys as key (key)}
                        <span class="key-chip">{key.label}</span>
                    {/each}
                </div>
            {/if}
        </div>
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

    .stage {
        position: relative;
        display: inline-block;
        max-width: 100%;
        line-height: 0;
    }

    canvas {
        display: block;
        max-width: 100%;
        image-rendering: pixelated;
        cursor: pointer;
    }

    .click-layer, .key-layer {
        position: absolute;
        pointer-events: none;
    }

    .click-layer {
        inset: 0;
    }

    .click-ring {
        position: absolute;
        width: 44px;
        height: 44px;
        margin: 0;
        border: 2px solid rgba(255, 255, 255, 0.9);
        border-radius: 50%;
        box-shadow: 0 0 6px rgba(0, 0, 0, 0.6);
    }

    .key-layer {
        left: 0;
        right: 0;
        bottom: 10px;
        display: flex;
        flex-wrap: wrap;
        justify-content: center;
        gap: 6px;
        padding: 0 10px;
        line-height: normal;
    }

    .key-chip {
        padding: 0.15rem 0.5rem;
        border-radius: 4px;
        background: rgba(0, 0, 0, 0.7);
        color: #fff;
        font-size: 0.85rem;
        font-family: var(--bs-font-monospace, monospace);
        white-space: nowrap;
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
