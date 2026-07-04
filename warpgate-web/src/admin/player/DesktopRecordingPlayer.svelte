<script lang="ts">
    import { onDestroy, onMount } from 'svelte'
    import { Spinner } from '@sveltestrap/sveltestrap'
    import type { Recording } from 'admin/lib/api'
    import { applyDesktopFrame, ensureCanvasSize, type DesktopFrame } from 'common/desktopCanvas'
    import { keysymLabel, scancodeLabel, type KeyPress, type Click } from 'common/desktopInput'
    import PlayerToolbar from './PlayerToolbar.svelte'
    import { latestWins } from './latestWins'

    // Playback modes. `live` tails the growing recording (deltas applied as they stream);
    // `playing` advances through recorded time; `paused` holds a frame. Grabbing the
    // scrubber pauses; "go live" enters `live`; play/pause toggles paused↔playing and
    // always leaves `live`.
    type PlayerMode = 'paused' | 'playing' | 'live'

    export let recording: Recording

    // How long a click ring animates / a pressed key stays on the overlay (seconds).
    const CLICK_ANIM_S = 0.6
    const KEY_DISPLAY_S = 3
    // Number of time buckets in the scrubber input-density heatmap.
    const HEATMAP_BUCKETS = 200

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
    // Lines of the append-only `index.ndjson`: seek anchors, size changes, input
    // timestamps (heatmap only) and a final duration marker. Overlay input comes from the
    // data stream, not here.
    type IndexLine =
        | { type: 'keyframe', time: number, offset: number }
        | { type: 'resize', time: number, width: number, height: number }
        | { type: 'input', time: number }
        | { type: 'end', time: number }

    let rootElement: HTMLDivElement
    let canvas: HTMLCanvasElement
    let ctx: CanvasRenderingContext2D | null = null

    let timestamp = 0
    let duration = 0
    let keyframes: { time: number, offset: number }[] = []
    // Per-bucket viewer-input density (0..1) drawn behind the scrubber.
    let heatmap: number[] = []

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
    let mode: PlayerMode = 'paused'
    let loading = true
    let sessionIsLive: boolean | null = null
    let socket: WebSocket | null = null
    let destroyed = false

    // --- streaming engine: pulls the ndjson via HTTP Range and applies frames in order,
    // discarding each (bounded memory). Seeks restart from the nearest keyframe. ---
    let reader: ReadableStreamDefaultReader<Uint8Array> | null = null
    let lineBuf = ''
    let pending: Frame | InputItem | null = null
    let renderedTime = 0
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
            throw new Error(`Failed to fetch index: ${response.status} ${response.statusText}`)
        }
        // Parse the whole (small) index once: seek anchors, input timestamps for the
        // heatmap, and the first resize so we can size the canvas at t=0.
        const text = await response.text()
        const inputTimes: number[] = []
        let firstResize: { width: number, height: number } | null = null
        for (const line of text.split('\n')) {
            if (!line.trim()) {
                continue
            }
            let entry: IndexLine
            try {
                entry = JSON.parse(line) as IndexLine
            } catch {
                continue
            }
            duration = Math.max(duration, entry.time)
            switch (entry.type) {
                case 'keyframe': keyframes.push({ time: entry.time, offset: entry.offset }); break
                case 'resize': firstResize ??= { width: entry.width, height: entry.height }; break
                case 'input': inputTimes.push(entry.time); break
                case 'end': duration = entry.time; break
            }
        }
        heatmap = computeHeatmap(inputTimes, duration)
        if (firstResize && ctx) {
            ensureCanvasSize(canvas, firstResize.width, firstResize.height)
            canvasW = canvas.width
            canvasH = canvas.height
        }

        // Await the first paint directly (nothing else is seeking yet) so we don't clear
        // `loading` before there's a frame on the canvas. A fresh (never-aborted) signal.
        await doSeek({ time: 0, keyframeSkip: false, goLive: false }, new AbortController().signal)

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
                goLive()
            }
        } else if ('end' in message) {
            sessionIsLive = false
            if (mode === 'live') {
                mode = 'paused'
            }
        } else if ('data' in message) {
            const item = message.data as (Frame | InputItem)
            if (typeof item.time === 'number') {
                duration = Math.max(duration, item.time)
            }
            recordInput(item)
            if (mode === 'live' && ctx && FRAME_TYPES.has(item.type)) {
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

    // Bucket viewer-input events by time into a 0..1 density curve for the scrubber
    // heatmap. Perceptual (sqrt) scaling so one high-rate burst (e.g. a window drag)
    // doesn't flatten every other bucket to invisibility.
    function computeHeatmap (times: number[], total: number): number[] {
        const buckets = new Array<number>(HEATMAP_BUCKETS).fill(0)
        if (total <= 0) {
            return buckets
        }
        for (const time of times) {
            const i = Math.min(HEATMAP_BUCKETS - 1, Math.max(0, Math.floor(HEATMAP_BUCKETS * time / total)))
            buckets[i] = (buckets[i] ?? 0) + 1
        }
        const max = Math.max(1, ...buckets)
        return buckets.map(c => Math.sqrt(c / max))
    }

    function abortReader () {
        reader?.cancel().catch(() => {})
        reader = null
        lineBuf = ''
        pending = null
    }

    async function openStreamAt (offset: number, signal: AbortSignal) {
        abortReader()
        // Pass the seek's signal so a superseded seek aborts this Range request instead of
        // downloading bytes we'll throw away.
        const response = await fetch(DATA_URL, { headers: { Range: `bytes=${offset}-` }, signal })
        reader = response.body?.getReader() ?? null
    }

    function parseItem (line: string): Frame | InputItem | null {
        try {
            return JSON.parse(line) as Frame | InputItem
        } catch {
            return null
        }
    }

    // Next item (frame or viewer-input) from the open stream; null at EOF.
    async function nextItem (): Promise<Frame | InputItem | null> {
        while (reader) {
            const nl = lineBuf.indexOf('\n')
            if (nl < 0) {
                const { done, value } = await reader.read()
                if (done) {
                    const rest = lineBuf.trim()
                    lineBuf = ''
                    return rest ? parseItem(rest) : null
                }
                lineBuf += decoder.decode(value, { stream: true })
                continue
            }
            const line = lineBuf.slice(0, nl).trim()
            lineBuf = lineBuf.slice(nl + 1)
            const item = line ? parseItem(line) : null
            if (item) {
                return item
            }
        }
        return null
    }

    // Play the stream up to `time`, unless a newer seek supersedes us: apply framebuffer
    // items to the canvas and feed viewer-input items to the overlay (the overlay is
    // rebuilt from the stream, not the index — see `doSeek`'s reset on reopen).
    async function pumpUntil (time: number, signal: AbortSignal) {
        while (ctx) {
            const item = pending ?? await nextItem()
            if (signal.aborted) {
                return
            }
            pending = null
            if (!item) {
                return
            }
            if (item.time > time) {
                pending = item
                return
            }
            if (FRAME_TYPES.has(item.type)) {
                await applyDesktopFrame(canvas, ctx, item as Frame)
                if (signal.aborted) {
                    return
                }
                renderedTime = item.time
                canvasW = canvas.width
                canvasH = canvas.height
            } else {
                recordInput(item as InputItem)
            }
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

    interface SeekRequest { time: number, keyframeSkip: boolean, goLive: boolean }

    // All seeks go through one latest-wins runner: rapid scrubs coalesce and a new seek
    // supersedes any in-flight one. `keyframeSkip` lets an explicit scrub jump forward to a
    // keyframe; playback stepping leaves it off so it renders every intermediate frame.
    const runSeek = latestWins((req: SeekRequest, signal) => doSeek(req, signal))

    function seek (time: number, keyframeSkip = false, goLive = false) {
        runSeek({ time: Math.max(0, Math.min(duration, time)), keyframeSkip, goLive })
    }

    async function doSeek (req: SeekRequest, signal: AbortSignal) {
        if (!ctx) {
            return
        }
        const { time, keyframeSkip, goLive } = req
        // Restart the stream at the keyframe ≤ time when we can't cheaply continue forward:
        // no open stream, seeking backward, or (on an explicit scrub) a keyframe lies
        // between our render position and the target — jumping beats replaying the deltas.
        const kf = keyframeBefore(time)
        if (!reader || time < renderedTime || (keyframeSkip && kf.time > renderedTime)) {
            await openStreamAt(kf.offset, signal)
            if (signal.aborted) {
                return
            }
            renderedTime = kf.time
            // The overlay is rebuilt from the stream as we pump forward; reset it so a
            // reopen doesn't duplicate clicks or desync button-transition detection.
            keyPresses = []
            clicks = []
            prevButtons = 0
        }
        await pumpUntil(time, signal)
        if (signal.aborted) {
            return
        }
        timestamp = time
        seekInputValue = duration ? 100 * time / duration : 0
        // Base is now the latest keyframe + deltas up to the live edge, so it's finally
        // safe to tail: applying incoming live deltas on a stale base is what froze it.
        if (goLive) {
            mode = 'live'
        }
    }

    // Jump to the live edge: a keyframe-based seek to the newest recorded frame (reusing
    // doSeek), then tail. Held paused during the rebase so playback stepping and live-apply
    // don't interfere; doSeek flips us to `live` once the correct base is painted.
    function goLive () {
        mode = 'paused'
        seek(duration, true, true)
    }

    function step () {
        if (destroyed) {
            return
        }
        if (mode === 'playing' && timestamp < duration) {
            seek(Math.min(duration, timestamp + 0.1))
        }
        setTimeout(step, 100)
    }

    function togglePlaying () {
        // Play/pause always leaves live tailing (pausing freezes the current frame).
        mode = mode === 'paused' ? 'playing' : 'paused'
    }

    // Grabbing the scrubber pauses and leaves live (so live deltas don't fight the scrub).
    function scrub (time: number) {
        mode = 'paused'
        seek(time, true)
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

    <div class="stage-container" class:invisible={loading}>
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

    <PlayerToolbar
        playing={mode !== 'paused'}
        {timestamp}
        {heatmap}
        bind:seekInputValue
        hidden={loading}
        isLive={sessionIsLive === true}
        liveActive={mode === 'live'}
        onTogglePlaying={togglePlaying}
        onToggleFullscreen={toggleFullscreen}
        onGoLive={goLive}
        onSeek={pct => scrub(duration * pct / 100)}
    />
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
        border: 1px solid #ffffff1a;
    }

    .stage-container {
        margin: auto;
        max-width: 100%;
        overflow: auto;

        // center in fullscreen
        flex-grow: 1;
        align-content: center;
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

    :global(.spinner-border) {
        position: absolute;
        left: 50%;
        top: 50%;
        margin: -12px 0 0 -12px;
        z-index: 1;
    }
</style>
