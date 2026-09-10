<script lang="ts">
    import { Spinner } from '@sveltestrap/sveltestrap'
    import type { Recording } from 'admin/lib/api'
    import {
        applyDesktopFrame,
        type DesktopFrame,
        ensureCanvasSize,
        isDesktopFrameType,
    } from 'common/desktopCanvas'
    import {
        type Click,
        type KeyPress,
        keysymLabel,
        scancodeLabel,
    } from 'common/desktopInput'
    import { onDestroy, onMount } from 'svelte'
    import PlayerToolbar from './PlayerToolbar.svelte'
    import { PlaybackController } from './playbackController'
    import type { Keyframe } from './rangeStream'

    export let recording: Recording

    // How long a click ring animates / a pressed key stays on the overlay (seconds).
    const CLICK_ANIM_S = 0.6
    const KEY_DISPLAY_S = 3
    // Number of time buckets in the scrubber input-density heatmap.
    const HEATMAP_BUCKETS = 200

    const DATA_URL = `/@warpgate/admin/api/recordings/${recording.id}/data`
    const INDEX_URL = `/@warpgate/admin/api/recordings/${recording.id}/index`
    const STREAM_URL = `wss://${location.host}/@warpgate/admin/api/recordings/${recording.id}/stream`

    type Frame = DesktopFrame & { time: number }
    type InputItem =
        | { type: 'key_input'; time: number; keysym: number; down: boolean }
        | {
              type: 'scancode_input'
              time: number
              code: number
              extended: boolean
              down: boolean
          }
        | {
              type: 'pointer_input'
              time: number
              x: number
              y: number
              buttons: number
          }
        | { type: 'wheel_input' | 'clipboard_input'; time: number }
    // Lines of the append-only `index.ndjson`: seek anchors, size changes, input
    // timestamps (heatmap only) and a final duration marker. Overlay input comes from the
    // data stream, not here.
    type IndexLine =
        | { type: 'keyframe'; time: number; offset: number }
        | { type: 'resize'; time: number; width: number; height: number }
        | { type: 'input'; time: number }
        | { type: 'end'; time: number }

    let rootElement: HTMLDivElement
    let canvas: HTMLCanvasElement
    let ctx: CanvasRenderingContext2D | null = null

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
    $: activeKeys = keyPresses.filter(
        k => k.time <= $timestamp && k.time > $timestamp - KEY_DISPLAY_S,
    )
    $: activeClicks = clicks.filter(
        c => c.time <= $timestamp && c.time > $timestamp - CLICK_ANIM_S,
    )
    let seekInputValue = 0
    let loading = true

    // Apply one item: framebuffer frames to the canvas, viewer input to the overlay.
    async function applyItem(item: Frame | InputItem) {
        if (!isDesktopFrameType(item.type)) {
            recordInput(item)
            return
        }
        if (!ctx) {
            return
        }
        await applyDesktopFrame(canvas, ctx, item as Frame)
        canvasW = canvas.width
        canvasH = canvas.height
    }

    const player = new PlaybackController<Frame | InputItem>(
        { data: DATA_URL, stream: STREAM_URL },
        {
            // The overlay is rebuilt from the stream as we pump forward; reset it so a
            // reopen doesn't duplicate clicks or desync button-transition detection.
            reset: (_kf: Keyframe) => {
                keyPresses = []
                clicks = []
                prevButtons = 0
            },
            apply: applyItem,
            // Only items past the snapshot edge reach here, so input is recorded exactly
            // once — items already in the snapshot are rebuilt from the file by the pump.
            applyLive: applyItem,
        },
    )

    const { mode, timestamp, duration, seekPercent, sessionIsLive } = player
    $: seekInputValue = $seekPercent

    onDestroy(() => player.destroy())

    onMount(async () => {
        if (recording.kind !== 'Desktop') {
            throw new Error('Invalid recording type')
        }
        ctx = canvas.getContext('2d')

        const response = await fetch(INDEX_URL)
        if (!response.ok) {
            throw new Error(
                `Failed to fetch index: ${response.status} ${response.statusText}`,
            )
        }
        // Parse the whole (small) index once: seek anchors, input timestamps for the
        // heatmap, and the first resize so we can size the canvas at t=0.
        const text = await response.text()
        const keyframes: Keyframe[] = []
        const inputTimes: number[] = []
        let total = 0
        let firstResize: { width: number; height: number } | null = null
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
            total = Math.max(total, entry.time)
            switch (entry.type) {
                case 'keyframe':
                    keyframes.push({ time: entry.time, offset: entry.offset })
                    break
                case 'resize':
                    firstResize ??= { width: entry.width, height: entry.height }
                    break
                case 'input':
                    inputTimes.push(entry.time)
                    break
                case 'end':
                    total = entry.time
                    break
            }
        }
        player.setIndex(keyframes, total)
        heatmap = computeHeatmap(inputTimes, total)
        if (firstResize && ctx) {
            ensureCanvasSize(canvas, firstResize.width, firstResize.height)
            canvasW = canvas.width
            canvasH = canvas.height
        }

        // Hold the spinner until there's a frame on the canvas.
        await player.paintInitial()
        player.start()
        loading = false
    })

    // Extract a viewer-input item into the overlay arrays. Ignores framebuffer items.
    // Clicks are button-press transitions.
    function recordInput(item: InputItem | Frame) {
        switch (item.type) {
            case 'key_input':
                if (item.down) {
                    keyPresses = [
                        ...keyPresses,
                        { time: item.time, label: keysymLabel(item.keysym) },
                    ]
                }
                break
            case 'scancode_input':
                if (item.down) {
                    keyPresses = [
                        ...keyPresses,
                        {
                            time: item.time,
                            label: scancodeLabel(item.code, item.extended),
                        },
                    ]
                }
                break
            case 'pointer_input': {
                const pressed = item.buttons & ~prevButtons
                prevButtons = item.buttons
                if (pressed) {
                    clicks = [
                        ...clicks,
                        { time: item.time, x: item.x, y: item.y },
                    ]
                }
                break
            }
        }
    }

    // Bucket viewer-input events by time into a 0..1 density curve for the scrubber
    // heatmap. Perceptual (sqrt) scaling so one high-rate burst (e.g. a window drag)
    // doesn't flatten every other bucket to invisibility.
    function computeHeatmap(times: number[], total: number): number[] {
        const buckets = new Array<number>(HEATMAP_BUCKETS).fill(0)
        if (total <= 0) {
            return buckets
        }
        for (const time of times) {
            const i = Math.min(
                HEATMAP_BUCKETS - 1,
                Math.max(0, Math.floor((HEATMAP_BUCKETS * time) / total)),
            )
            buckets[i] = (buckets[i] ?? 0) + 1
        }
        const max = Math.max(1, ...buckets)
        return buckets.map(c => Math.sqrt(c / max))
    }

    function toggleFullscreen() {
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
            <canvas
                bind:this={canvas}
                on:click={() => player.togglePlaying()}
                role="img"
            ></canvas>

            <div class="click-layer">
                {#each activeClicks as click (click)}
                    {@const progress = ($timestamp - click.time) / CLICK_ANIM_S}
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
        playing={$mode !== 'paused'}
        timestamp={$timestamp}
        {heatmap}
        bind:seekInputValue
        hidden={loading}
        isLive={$sessionIsLive === true}
        liveActive={$mode === 'live'}
        onTogglePlaying={() => player.togglePlaying()}
        onToggleFullscreen={toggleFullscreen}
        onGoLive={() => player.goLive()}
        onSeek={pct => player.scrub($duration * pct / 100)}
    />
</div>

<style lang="scss">
    $min-height: 300px;

    .root {
        border-radius: 5px;
        overflow: hidden;
        position: relative;
        contain: content;
        display: flex;
        flex-direction: column;
        background: #262626;
        border: 1px solid #ffffff1a;
        flex: 1 0 0;

        min-height: $min-height;
    }

    .stage-container {
        margin: auto;
        max-width: 100%;
        overflow: auto;
        display: flex;
        flex-direction: column;

        // center in fullscreen
        flex-grow: 1;
        align-content: center;

        align-items: center;
        justify-content: center;
    }

    .stage {
        position: relative;
        display: inline-block;
        max-width: 100%;
        max-height: 100%;
        flex: 1 0 0;
    }

    canvas {
        display: block;
        max-width: 100%;
        max-height: 100%;
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
