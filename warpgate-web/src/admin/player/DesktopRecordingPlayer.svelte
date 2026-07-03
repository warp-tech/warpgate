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

    const DATA_URL = `/@warpgate/admin/api/recordings/${recording.id}/desktop`
    const INDEX_URL = `${DATA_URL}/index`

    // Framebuffer message types (everything else on the stream is a viewer-input item).
    const FRAME_TYPES = new Set(['resize', 'raw_image', 'png_image', 'jpeg_image', 'copy_rect', 'cursor'])

    type Frame = DesktopFrame & { time: number }
    type InputItem =
        | { type: 'key_input', time: number, keysym: number, down: boolean }
        | { type: 'scancode_input', time: number, code: number, down: boolean }
        | { type: 'pointer_input', time: number, x: number, y: number, buttons: number }
        | { type: 'wheel_input' | 'clipboard_input', time: number }
    interface DesktopIndex {
        duration: number
        keyframes: { time: number, offset: number }[]
        input: InputItem[]
    }

    let rootElement: HTMLDivElement
    let canvas: HTMLCanvasElement
    let ctx: CanvasRenderingContext2D | null = null

    let timestamp = 0
    let duration = 0
    let keyframes: { time: number, offset: number }[] = []

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
    let notPlayable = false
    let sessionIsLive: boolean | null = null
    let liveTailing = false
    let socket: WebSocket | null = null
    let destroyed = false

    // --- streaming engine: pulls the ndjson via HTTP Range and applies frames in order,
    // discarding each (bounded memory). Seeks restart from the nearest keyframe. ---
    let reader: ReadableStreamDefaultReader<Uint8Array> | null = null
    let lineBuf = ''
    let pending: Frame | null = null
    let renderedTime = 0
    let seekGen = 0
    const decoder = new TextDecoder()

    onDestroy(() => {
        destroyed = true
        abortReader()
        socket?.close()
    })

    onMount(async () => {
        if (recording.kind !== 'Desktop') {
            throw new Error('Invalid recording type')
        }
        ctx = canvas.getContext('2d')

        const response = await fetch(INDEX_URL)
        if (!response.ok) {
            // gen-1 desktop recordings have no index and aren't supported.
            notPlayable = true
            loading = false
            return
        }
        const index = await response.json() as DesktopIndex
        duration = index.duration
        keyframes = index.keyframes ?? []
        for (const item of index.input ?? []) {
            recordInput(item)
        }

        await seek(0)

        socket = new WebSocket(`wss://${location.host}${DATA_URL}-stream`)
        socket.addEventListener('message', event => onLiveMessage(JSON.parse(event.data)))
        socket.addEventListener('close', () => console.info('Live stream closed'))

        loading = false
        step()
    })

    function onLiveMessage (message: Record<string, unknown>) {
        if ('start' in message) {
            sessionIsLive = Boolean(message.live)
            if (sessionIsLive) {
                playing = true
                goLive()
            }
        } else if ('end' in message) {
            sessionIsLive = false
            liveTailing = false
        } else if ('data' in message) {
            const item = message.data as (Frame | InputItem)
            if (typeof item.time === 'number') {
                duration = Math.max(duration, item.time)
            }
            recordInput(item)
            if (liveTailing && ctx && FRAME_TYPES.has(item.type)) {
                void applyDesktopFrame(canvas, ctx, item as Frame).then(() => {
                    renderedTime = item.time
                    timestamp = item.time
                    canvasW = canvas.width
                    canvasH = canvas.height
                    seekInputValue = duration ? 100 * timestamp / duration : 0
                })
            }
        }
    }

    // Extract a viewer-input item into the overlay arrays. Ignores framebuffer items.
    // Clicks are button-press transitions.
    function recordInput (item: InputItem | Frame) {
        switch (item.type) {
            case 'key_input':
                if (item.down) {
                    keyPresses = [...keyPresses, { time: item.time, label: keysymLabel(item.keysym) }]
                }
                break
            case 'scancode_input':
                if (item.down) {
                    keyPresses = [...keyPresses, { time: item.time, label: scancodeLabel(item.code) }]
                }
                break
            case 'pointer_input': {
                const pressed = item.buttons & ~prevButtons
                prevButtons = item.buttons
                if (pressed) {
                    clicks = [...clicks, { time: item.time, x: item.x, y: item.y }]
                }
                break
            }
        }
    }

    function abortReader () {
        reader?.cancel().catch(() => {})
        reader = null
        lineBuf = ''
        pending = null
    }

    async function openStreamAt (offset: number) {
        abortReader()
        const response = await fetch(DATA_URL, { headers: { Range: `bytes=${offset}-` } })
        reader = response.body?.getReader() ?? null
    }

    function parseFrame (line: string): Frame | null {
        try {
            const item = JSON.parse(line)
            return FRAME_TYPES.has(item.type) ? item as Frame : null
        } catch {
            return null
        }
    }

    // Next framebuffer item from the open stream (skips input items); null at EOF.
    async function nextFrame (): Promise<Frame | null> {
        while (reader) {
            const nl = lineBuf.indexOf('\n')
            if (nl < 0) {
                const { done, value } = await reader.read()
                if (done) {
                    const rest = lineBuf.trim()
                    lineBuf = ''
                    return rest ? parseFrame(rest) : null
                }
                lineBuf += decoder.decode(value, { stream: true })
                continue
            }
            const line = lineBuf.slice(0, nl).trim()
            lineBuf = lineBuf.slice(nl + 1)
            const frame = line ? parseFrame(line) : null
            if (frame) {
                return frame
            }
        }
        return null
    }

    // Apply frames from the open stream up to `time`, unless a newer seek supersedes us.
    async function pumpUntil (time: number, gen: number) {
        while (ctx) {
            const frame = pending ?? await nextFrame()
            if (gen !== seekGen) {
                return
            }
            pending = null
            if (!frame) {
                return
            }
            if (frame.time > time) {
                pending = frame
                return
            }
            await applyDesktopFrame(canvas, ctx, frame)
            if (gen !== seekGen) {
                return
            }
            renderedTime = frame.time
            canvasW = canvas.width
            canvasH = canvas.height
        }
    }

    function keyframeBefore (time: number): { time: number, offset: number } {
        let best = { time: 0, offset: 0 }
        for (const kf of keyframes) {
            if (kf.time > time) {
                break
            }
            best = kf
        }
        return best
    }

    // Coalesced, one-at-a-time seek (async apply must not run concurrently).
    let seeking = false
    let queuedSeek: number | null = null
    async function seek (time: number) {
        queuedSeek = Math.max(0, Math.min(duration, time))
        if (seeking) {
            return
        }
        seeking = true
        try {
            while (queuedSeek !== null) {
                const target = queuedSeek
                queuedSeek = null
                await doSeek(target)
            }
        } finally {
            seeking = false
        }
    }

    async function doSeek (time: number) {
        if (!ctx) {
            return
        }
        liveTailing = false
        const gen = ++seekGen
        // Continue the open stream when moving forward; otherwise restart at the keyframe ≤ time.
        if (!reader || time < renderedTime) {
            const kf = keyframeBefore(time)
            await openStreamAt(kf.offset)
            if (gen !== seekGen) {
                return
            }
            renderedTime = kf.time
        }
        await pumpUntil(time, gen)
        if (gen !== seekGen) {
            return
        }
        timestamp = time
        seekInputValue = duration ? 100 * time / duration : 0
    }

    function goLive () {
        liveTailing = true
        abortReader()
        timestamp = duration
        seekInputValue = 100
    }

    async function step () {
        if (destroyed) {
            return
        }
        if (playing && !liveTailing && !seeking && timestamp < duration) {
            await seek(Math.min(duration, timestamp + 0.1))
        }
        if (!destroyed) {
            setTimeout(() => void step(), 100)
        }
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

    {#if notPlayable}
        <div class="not-playable">This recording predates indexed playback and can't be played.</div>
    {/if}

    <div class="container" class:invisible={loading || notPlayable}>
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

    <div class="toolbar" class:invisible={loading || notPlayable}>
        <button class="btn btn-link" on:click={togglePlaying}>
            <Fa icon={playing ? faPause : faPlay} fw />
        </button>
        <pre class="timestamp">{ formatDuration(timestamp * 1000, { leading: true }) }</pre>
        {#if sessionIsLive === true}
            <button
                class="btn live-btn"
                class:active={liveTailing}
                on:click={goLive}
            >LIVE</button>
        {/if}
        <input
            class="w-100"
            type="range"
            min="0" max="100" step="0.001"
            style="background-size: {seekInputValue}% 100%;"
            bind:value={seekInputValue}
            on:input={() => void seek(duration * seekInputValue / 100)} />
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

    .not-playable {
        color: #eee;
        padding: 2rem;
        text-align: center;
        font-size: 0.9rem;
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
