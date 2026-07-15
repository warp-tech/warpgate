<script lang="ts">
    import { faPlay } from '@fortawesome/free-solid-svg-icons'
    import { Spinner } from '@sveltestrap/sveltestrap'
    import { SerializeAddon } from '@xterm/addon-serialize'
    import { Terminal } from '@xterm/xterm'
    import type { Recording } from 'admin/lib/api'
    import { LiveRecordingStream } from 'common/liveRecordingStream'
    import { onDestroy, onMount } from 'svelte'
    import Fa from 'svelte-fa'
    import { latestWins } from './latestWins'
    import PlayerToolbar from './PlayerToolbar.svelte'

    export let recording: Recording

    let url: string
    let containerElement: HTMLDivElement
    let rootElement: HTMLDivElement
    let timestamp = 0
    let seekInputValue = 0
    let duration = 0
    let resizeObserver: ResizeObserver | undefined
    let events: (DataEvent | SizeEvent | SnapshotEvent)[] = []
    let playing = false
    let loading = true
    let sessionIsLive: boolean | null = null
    let stream: LiveRecordingStream | null = null
    let isStreaming = false
    let ptyMode = false

    $: isStreaming = timestamp === duration && playing

    const COLOR_NAMES = [
        'black',
        'red',
        'green',
        'yellow',
        'blue',
        'magenta',
        'cyan',
        'white',
        'brightBlack',
        'brightRed',
        'brightGreen',
        'brightYellow',
        'brightBlue',
        'brightMagenta',
        'brightCyan',
        'brightWhite',
    ]

    const theme: Record<string, string> = {
        foreground: '#ffcb83',
        background: '#262626',
        cursor: '#fc531d',
    }
    const colors = [
        '#000000',
        '#c13900',
        '#a4a900',
        '#caaf00',
        '#bd6d00',
        '#fc5e00',
        '#f79500',
        '#ffc88a',
        '#6a4f2a',
        '#ff8c68',
        '#f6ff40',
        '#ffe36e',
        '#ffbe55',
        '#fc874f',
        '#c69752',
        '#fafaff',
    ]
    for (let i = 0; i < COLOR_NAMES.length; i++) {
        // biome-ignore lint/style/noNonNullAssertion: x
        theme[COLOR_NAMES[i]!] = colors[i]!
    }

    // The raw stored item: `data` is base64 of the exact terminal bytes (lossless
    // at rest). The lossy decode for display happens in `addTerminalItem`.
    type TerminalItem =
        | { time: number; stream?: 'Input' | 'Output' | 'Error'; data: string }
        | { time: number; cols: number; rows: number }

    function decodeBase64Lossy(b64: string): string {
        const bin = atob(b64)
        const bytes = new Uint8Array(bin.length)
        for (let i = 0; i < bin.length; i++) {
            bytes[i] = bin.charCodeAt(i)
        }
        // fatal:false replaces invalid sequences with U+FFFD — same as the
        // server's former from_utf8_lossy.
        return new TextDecoder('utf-8', { fatal: false }).decode(bytes)
    }

    interface SizeEvent {
        time: number
        cols: number
        rows: number
    }
    interface DataEvent {
        time: number
        data: string
    }
    interface SnapshotEvent {
        time: number
        snapshot: string
    }

    const term = new Terminal()
    const serializeAddon = new SerializeAddon()

    onDestroy(() => stream?.close())

    onMount(async () => {
        if (recording.kind !== 'Terminal') {
            throw new Error('Invalid recording type')
        }

        url = `/@warpgate/admin/api/recordings/${recording.id}/data`

        term.loadAddon(serializeAddon)
        term.open(containerElement)

        term.options.theme = theme
        term.options.scrollback = 100

        fitSize()
        resizeObserver = new ResizeObserver(fitSize)
        resizeObserver.observe(containerElement)

        // Subscribe and buffer BEFORE reading history so nothing written during
        // the fetch is lost; the stream then drops live items the snapshot
        // already covers (by byte offset) and tails the rest.
        let painted = false
        let started = false

        function applyLiveDecision() {
            if (!painted || !started) {
                return
            }
            if (sessionIsLive) {
                playing = true
            } else {
                seek(0)
            }
        }

        stream = new LiveRecordingStream(
            `wss://${location.host}/@warpgate/admin/api/recordings/${recording.id}/stream`,
            {
                onStart: live => {
                    started = true
                    sessionIsLive = live
                    applyLiveDecision()
                },
                onEnd: () => {
                    sessionIsLive = false
                },
                onNext: item => addTerminalItem(item as TerminalItem),
            },
        )
        stream.arm()

        // Read the raw file as bytes so the snapshot boundary is exact (the
        // decompressed byte length), independent of any transfer encoding.
        const buf = await fetch(url).then(r => r.arrayBuffer())
        for (const line of new TextDecoder().decode(buf).split('\n')) {
            if (!line) {
                continue
            }
            addTerminalItem(JSON.parse(line) as TerminalItem)
        }
        await stream.splice(buf.byteLength)

        // Await the first paint directly (nothing else is seeking yet) so `loading` clears
        // only once the terminal reflects the recording.
        await _seekInternal(duration)
        painted = true
        applyLiveDecision()

        loading = false
    })

    async function writeToTerminal(data: string) {
        if (!ptyMode) {
            data = data.replace(/\n/g, '\r\n')
        }
        await new Promise<void>(r => term.write(data, r))
    }

    // Fold one stored item into the player's event model. Viewer input isn't
    // rendered, matching the previous server-side behaviour.
    function addTerminalItem(item: TerminalItem) {
        if ('cols' in item) {
            if (item.cols) {
                ptyMode = true
            }
            events.push({ time: item.time, cols: item.cols, rows: item.rows })
            if (isStreaming) {
                resize(item.cols, item.rows)
                timestamp = item.time
            }
            duration = Math.max(duration, item.time)
            return
        }
        if (item.stream === 'Input') {
            return
        }
        const data = decodeBase64Lossy(item.data)
        events.push({ time: item.time, data })
        if (isStreaming) {
            writeToTerminal(data)
            timestamp = item.time
        }
        duration = Math.max(duration, item.time)
    }

    let metricsCanvas: HTMLCanvasElement
    function fitSize() {
        metricsCanvas ??= document.createElement('canvas')
        const context = metricsCanvas.getContext('2d')
        if (!context) {
            throw new Error('Failed to get canvas context')
        }
        context.font = `10px ${term.options.fontFamily ?? 'monospace'}`
        const metrics = context.measureText('abcdef')

        const fontWidth = containerElement.clientWidth / term.cols
        term.options.fontSize = (fontWidth / (metrics.width / 6)) * 10
    }

    // Shared latest-wins runner: serializes seeks and coalesces rapid scrubs to the newest
    // target (replaying the terminal to an intermediate position we're about to leave is
    // wasted work). Reconstructing state at `time` is independent of skipped seeks.
    const runSeek = latestWins((time: number) => _seekInternal(time))

    function seek(time: number) {
        runSeek(time)
    }

    async function _seekInternal(time: number) {
        let nearestSnapshot: SnapshotEvent | null = null

        for (const event of events) {
            if (event.time > time) {
                break
            }
            if ('snapshot' in event) {
                nearestSnapshot = event
            }
        }

        let index = nearestSnapshot ? events.indexOf(nearestSnapshot) : 0
        if (time >= timestamp) {
            const nextEventIndex = events.findIndex(e => e.time > timestamp)
            if (nextEventIndex === -1) {
                return
            }
            index = Math.max(index, nextEventIndex)
        }
        let lastSize = { cols: term.cols, rows: term.rows }

        for (let i = 0; i <= index; i++) {
            // biome-ignore lint/style/noNonNullAssertion: x
            let event = events[i]!
            if ('cols' in event) {
                lastSize = { cols: event.cols, rows: event.rows }
            }
        }

        resize(lastSize.cols, lastSize.rows)

        let output = ''

        async function flush() {
            await writeToTerminal(output)
            output = ''
        }

        for (let i = index; i < events.length; i++) {
            let shouldSnapshot = false
            // biome-ignore lint/style/noNonNullAssertion: x
            let event = events[i]!
            if (event.time > time) {
                break
            }
            if ('snapshot' in event) {
                output += `\x1bc${event.snapshot}`
            }
            if ('cols' in event) {
                await flush()
                resize(event.cols, event.rows)
                shouldSnapshot = true
            }
            if ('data' in event) {
                output += event.data
            }

            shouldSnapshot ||= output.length > 1000

            if (shouldSnapshot) {
                await flush()
                events.splice(i + 1, 0, {
                    time: event.time,
                    snapshot: serializeAddon.serialize(),
                })
                i++
            }
        }

        await flush()

        timestamp = time
        seekInputValue = (100 * time) / duration
    }

    function resize(cols: number, rows: number) {
        if (term.cols === cols && term.rows === rows) {
            return
        }
        if (cols && rows) {
            term.resize(cols, rows)
        }
        fitSize()
    }

    onDestroy(() => resizeObserver?.disconnect())

    let destroyed = false
    onDestroy(() => (destroyed = true))

    function step() {
        if (destroyed) {
            return
        }
        if (playing) {
            seek(Math.min(duration, timestamp + 0.1))
        }
        setTimeout(step, 100)
    }

    function togglePlaying() {
        playing = !playing
    }

    function keyPressHandler(event: KeyboardEvent) {
        if (event.key === ' ') {
            togglePlaying()
        }
    }

    step()

    function toggleFullscreen() {
        if (document.fullscreenElement) {
            document.exitFullscreen()
        } else {
            rootElement.requestFullscreen()
        }
    }
</script>

<div
    class="root"
    bind:this={rootElement}
    style="background: {theme.background}"
>
    {#if loading}
        <Spinner color="primary" />
    {/if}

    {#if !loading && !playing}
        <div class="pause-overlay">
            <Fa icon={faPlay} size="2x" fw />
        </div>
    {/if}

    <!-- svelte-ignore a11y-no-noninteractive-element-interactions -->
    <div
        class="container"
        class:invisible={loading}
        on:click={togglePlaying}
        on:keypress={keyPressHandler}
        role="img"
        bind:this={containerElement}
    ></div>

    <PlayerToolbar
        {playing}
        {timestamp}
        bind:seekInputValue
        hidden={loading}
        isLive={sessionIsLive === true}
        liveActive={isStreaming}
        onTogglePlaying={togglePlaying}
        onToggleFullscreen={toggleFullscreen}
        onGoLive={() => seek(duration)}
        onSeek={pct => seek(duration * pct / 100)}
    />
</div>

<style lang="scss">
    @import "../../../node_modules/@xterm/xterm/css/xterm.css";

    .root {
        border-radius: 5px;
        overflow: hidden;
        position: relative;
        contain: content;
        display: flex;
        flex-direction: column;
    }

    .container {
        padding: 5px;
        margin: auto;
    }

    :global(.xterm) {
        cursor: pointer !important;
    }

    :global(.spinner-border), .pause-overlay {
        position: absolute;
        left: 50%;
        top: 50%;
        margin: -12px 0 0 -12px;
        z-index: 1;
    }

    .pause-overlay {
        width: 24px;
        text-align: center;
        color: white;
    }
</style>
