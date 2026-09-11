<script lang="ts">
    import { faPlay } from '@fortawesome/free-solid-svg-icons'
    import { Spinner } from '@sveltestrap/sveltestrap'
    import { Terminal } from '@xterm/xterm'
    import type { Recording } from 'admin/lib/api'
    import formatDuration from 'format-duration'
    import { onDestroy, onMount } from 'svelte'
    import Fa from 'svelte-fa'
    import PlayerToolbar from './PlayerToolbar.svelte'
    import { PlaybackController } from './playbackController'
    import { type Keyframe, RangeStream } from './rangeStream'

    interface Props {
        recording: Recording
    }

    let { recording }: Props = $props()

    // The first generation whose terminal recordings carry an `index.ndjson` sidecar.
    const INDEXED_GENERATION = 3
    // Replayed bytes are batched into xterm rather than written per recorded chunk.
    const WRITE_BATCH_CHARS = 8192

    // Content search: how many matches to collect before stopping the scan,
    // and how much of an un-newlined tail to keep for boundary-spanning matches.
    const MAX_SEARCH_MATCHES = 500
    const MAX_SEARCH_TAIL = 16 * 1024
    const SEARCH_CONTEXT_BEFORE = 30
    const SEARCH_CONTEXT_AFTER = 60

    const DATA_URL = `/@warpgate/admin/api/recordings/${recording.id}/data`
    const INDEX_URL = `/@warpgate/admin/api/recordings/${recording.id}/index`
    const STREAM_URL = `wss://${location.host}/@warpgate/admin/api/recordings/${recording.id}/stream`

    let containerElement: HTMLDivElement
    let rootElement: HTMLDivElement
    let resizeObserver: ResizeObserver | undefined
    let loading = true
    let ptyMode = false

    interface SearchMatch {
        time: number
        before: string
        hit: string
        after: string
    }

    let searchMatches: SearchMatch[] | null = $state(null)
    let searchTruncated = $state(false)
    let searchScanning = $state(false)
    let searchError: string | null = $state(null)
    let searchController: AbortController | null = null

    // Terminal sizes over time, from the index: a snapshot has to be restored at the size
    // it was taken at.
    let sizes: { time: number; cols: number; rows: number }[] = []
    // Set while the stream sits exactly on a keyframe, so the snapshot there is applied.
    // Snapshots met while playing forward are redundant — the screen already holds that
    // state — and applying one would reset the terminal, throwing away the scrollback.
    let atKeyframe = false
    let pendingWrite = ''

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

    // The raw stored items: `data`/`snapshot` are base64 of the exact terminal bytes
    // (lossless at rest). The lossy decode for display happens on the way to xterm.
    // A `snapshot` is a seek anchor: escape codes reproducing the whole screen.
    type TerminalItem =
        | { time: number; snapshot: string }
        | { time: number; stream?: 'Input' | 'Output' | 'Error'; data: string }
        | { time: number; cols: number; rows: number }

    // Lines of the append-only `index.ndjson`: seek anchors, the size to restore them at,
    // and a final duration marker.
    type IndexLine =
        | { type: 'keyframe'; time: number; offset: number }
        | { type: 'resize'; time: number; cols: number; rows: number }
        | { type: 'end'; time: number }

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

    const term = new Terminal()

    const player = new PlaybackController<TerminalItem>(
        { data: DATA_URL, stream: STREAM_URL },
        {
            // The anchor's snapshot repaints the screen at the size it was taken; reset
            // first so nothing from the position we're leaving survives.
            reset: async (kf: Keyframe) => {
                const size = sizeAt(kf.time)
                if (size) {
                    resize(size.cols, size.rows)
                }
                pendingWrite = ''
                await writeToTerminal('\x1bc')
                atKeyframe = true
            },
            apply: async item => {
                if ('cols' in item) {
                    await flush()
                    ptyMode ||= Boolean(item.cols)
                    resize(item.cols, item.rows)
                } else if ('snapshot' in item) {
                    if (atKeyframe) {
                        pendingWrite += decodeBase64Lossy(item.snapshot)
                    }
                } else if (item.stream !== 'Input') {
                    pendingWrite += decodeBase64Lossy(item.data)
                }
                atKeyframe = false
                if (pendingWrite.length > WRITE_BATCH_CHARS) {
                    await flush()
                }
            },
            // Snapshots are skipped: they only restate what the stream already put on screen.
            applyLive: async item => {
                if ('cols' in item) {
                    ptyMode ||= Boolean(item.cols)
                    resize(item.cols, item.rows)
                } else if ('data' in item && item.stream !== 'Input') {
                    await writeToTerminal(decodeBase64Lossy(item.data))
                }
            },
            flush,
        },
    )

    const { mode, timestamp, duration, seekPercent, sessionIsLive } = player
    let seekInputValue = $derived($seekPercent)

    onDestroy(() => {
        player.destroy()
        searchController?.abort()
        resizeObserver?.disconnect()
    })

    onMount(async () => {
        if (recording.kind !== 'Terminal') {
            throw new Error('Invalid recording type')
        }

        term.open(containerElement)
        term.options.theme = theme
        term.options.scrollback = 100

        fitSize()
        resizeObserver = new ResizeObserver(fitSize)
        resizeObserver.observe(containerElement)

        if (recording.generation >= INDEXED_GENERATION) {
            await loadIndex()
        } else {
            await fakeIndex()
        }

        // Hold the spinner until the terminal reflects the recording.
        await player.paintInitial()
        player.start()
        loading = false
    })

    // Parse the whole (small) index once: seek anchors, the sizes to restore them at, and
    // the total duration.
    async function loadIndex() {
        const response = await fetch(INDEX_URL)
        if (!response.ok) {
            throw new Error(
                `Failed to fetch index: ${response.status} ${response.statusText}`,
            )
        }
        const keyframes: Keyframe[] = []
        let total = 0
        for (const line of (await response.text()).split('\n')) {
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
                    sizes.push(entry)
                    ptyMode ||= Boolean(entry.cols)
                    break
                case 'end':
                    total = entry.time
                    break
            }
        }
        player.setIndex(keyframes, total)
    }

    // Recordings written before the index existed get one trivial anchor at the start of
    // the file, which is always valid — a fresh terminal replayed from byte 0 is correct.
    // Their duration isn't recorded anywhere, so stream the file once to find it (the
    // items are parsed for their timestamps and dropped, never retained).
    async function fakeIndex() {
        const scan = new RangeStream(DATA_URL)
        await scan.openAt(0, new AbortController().signal)
        let total = 0
        for (;;) {
            const item = await scan.next<TerminalItem>()
            if (!item) {
                break
            }
            total = Math.max(total, item.time)
            if ('cols' in item) {
                ptyMode ||= Boolean(item.cols)
            }
        }
        scan.abort()
        player.setIndex([{ time: 0, offset: 0 }], total)
    }

    async function writeToTerminal(data: string) {
        if (!ptyMode) {
            data = data.replace(/\n/g, '\r\n')
        }
        await new Promise<void>(r => term.write(data, r))
    }

    async function flush() {
        const pending = pendingWrite
        pendingWrite = ''
        if (pending) {
            await writeToTerminal(pending)
        }
    }

    // ── Content search ─────────────────────────────────────────────────────────
    //
    // Streams the whole `data.ndjson` through a second RangeStream (memory-bounded,
    // same as playback), searching the visible (non-Input) streams. Matches are
    // line-based: ANSI escapes are stripped and \n splits chunks into candidate
    // lines; the last partial line carries over a bounded tail so matches that
    // span chunk boundaries are still found.

    // ESC-prefixed sequences: CSI (...m etc.), OSC (title, ended by BEL or ST),
    // and the two-character ones (DECSC, IND, ...). Runs of remaining C0
    // controls (a bare CR from a progress bar, tabs) collapse into a space.
    const ANSI_PATTERN =
        // biome-ignore lint/suspicious/noControlCharactersInRegex: matching escape bytes is the point
        /\x1b\[[0-9;:<=>?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?|\x1b[@-Z\\-_]/g

    function stripAnsi(text: string): string {
        return (
            text
                .replace(ANSI_PATTERN, '')
                // biome-ignore lint/suspicious/noControlCharactersInRegex: matching control bytes is the point
                .replace(/[\x00-\x09\x0b-\x1f\x7f]+/g, ' ')
        )
    }

    async function runSearch(query: string) {
        searchController?.abort()
        const trimmed = query.trim()
        if (!trimmed) {
            searchMatches = null
            searchTruncated = false
            searchError = null
            return
        }
        const controller = new AbortController()
        searchController = controller
        const signal = controller.signal
        searchScanning = true
        searchError = null
        searchTruncated = false

        const matches: SearchMatch[] = []
        let truncated = false
        const needle = trimmed.toLowerCase()

        const collect = (line: string, time: number) => {
            const haystack = line.toLowerCase()
            let index = haystack.indexOf(needle)
            while (index >= 0) {
                matches.push({
                    time,
                    before: line.slice(
                        Math.max(0, index - SEARCH_CONTEXT_BEFORE),
                        index,
                    ),
                    hit: line.slice(index, index + trimmed.length),
                    after: line.slice(
                        index + trimmed.length,
                        index + trimmed.length + SEARCH_CONTEXT_AFTER,
                    ),
                })
                if (matches.length >= MAX_SEARCH_MATCHES) {
                    truncated = true
                    return
                }
                index = haystack.indexOf(needle, index + trimmed.length)
            }
        }

        try {
            const scan = new RangeStream(DATA_URL)
            await scan.openAt(0, signal)
            let tail = ''
            let lastTime = 0
            for (;;) {
                const item = await scan.next<TerminalItem>()
                if (!item) {
                    break
                }
                if (signal.aborted) {
                    return
                }
                if ('data' in item && item.stream !== 'Input') {
                    lastTime = item.time
                    tail += decodeBase64Lossy(item.data)
                    if (tail.length > MAX_SEARCH_TAIL) {
                        tail = tail.slice(-MAX_SEARCH_TAIL)
                    }
                    const lines = tail.split('\n')
                    tail = lines.pop() ?? ''
                    for (const line of lines) {
                        collect(stripAnsi(line), item.time)
                        if (truncated) {
                            break
                        }
                    }
                    if (truncated) {
                        break
                    }
                }
            }
            if (!truncated && tail) {
                // The file's last line had no terminating newline.
                collect(stripAnsi(tail), lastTime)
            }
            if (!signal.aborted) {
                searchMatches = matches
                searchTruncated = truncated
            }
        } catch (error) {
            if (!signal.aborted) {
                searchError =
                    error instanceof Error ? error.message : String(error)
            }
        } finally {
            if (searchController === controller) {
                searchScanning = false
                searchController = null
            }
        }
    }

    // The terminal size in effect at `time`, or null when the recording has no size
    // information before it (an exec channel, or a pre-index recording).
    function sizeAt(time: number): { cols: number; rows: number } | null {
        let best: { cols: number; rows: number } | null = null
        for (const size of sizes) {
            if (size.time > time) {
                break
            }
            best = size
        }
        return best
    }

    let metricsCanvas: HTMLCanvasElement
    function fitSize() {
        metricsCanvas ??= document.createElement('canvas')
        const context = metricsCanvas.getContext('2d')
        if (!context) {
            throw new Error('Failed to get canvas context')
        }
        const probeFontSize = 100
        context.font = `${probeFontSize}px ${term.options.fontFamily ?? 'monospace'}`
        const metrics = context.measureText('W')

        const fontWidthRatio = metrics.width / probeFontSize
        const fontHeightRatio =
            (metrics.fontBoundingBoxAscent + metrics.fontBoundingBoxDescent) /
            probeFontSize
        const fontMaxWidth = containerElement.clientWidth / term.cols
        const fontMaxHeight = containerElement.clientHeight / term.rows
        term.options.fontSize = Math.floor(
            Math.min(
                fontMaxWidth / fontWidthRatio,
                fontMaxHeight /
                    fontHeightRatio /
                    (term.options.lineHeight ?? 1),
            ),
        )
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

    {#if !loading && $mode === 'paused'}
        <button
            type="button"
            class="pause-overlay"
            on:click={() => player.togglePlaying()}
        >
            <Fa icon={faPlay} size="2x" fw />
        </button>
    {/if}

    <!-- svelte-ignore a11y-no-noninteractive-element-interactions -->
    <!-- svelte-ignore a11y-click-events-have-key-events -->
    <div
        class="container"
        class:invisible={loading}
        on:click={() => player.togglePlaying()}
        role="img"
        bind:this={containerElement}
    ></div>

    {#if searchScanning || searchError || searchMatches !== null}
        <div class="search-results">
            <div class="search-header">
                {#if searchScanning}
                    <span class="text-muted">
                        Searching… {searchMatches?.length ?? 0} found
                    </span>
                {:else if searchError}
                    <span class="text-danger"
                        >Search failed: {searchError}</span
                    >
                {:else}
                    <span class="text-muted">
                        {searchMatches?.length ?? 0}
                        {(searchMatches?.length ?? 0) === 1 ? 'match' : 'matches'}
                        {#if searchTruncated}
                            (showing first {MAX_SEARCH_MATCHES})
                        {/if}
                    </span>
                {/if}
                <button
                    type="button"
                    class="btn-close btn-close-white ms-auto"
                    aria-label="Close search results"
                    on:click={() => runSearch('')}
                ></button>
            </div>
            {#if searchMatches?.length}
                <ul class="list-unstyled mb-0">
                    {#each searchMatches as match, i (i)}
                        <li>
                            <button
                                type="button"
                                title="Jump to this point"
                                on:click={() => player.seek(match.time, true)}
                            >
                                <span class="match-time">
                                    {formatDuration(match.time * 1000, { leading: true })}
                                </span>
                                <span class="match-line">
                                    <span class="context">{match.before}</span
                                    ><mark>{match.hit}</mark
                                    ><span class="context">{match.after}</span>
                                </span>
                            </button>
                        </li>
                    {/each}
                </ul>
            {/if}
        </div>
    {/if}

    <PlayerToolbar
        playing={$mode !== 'paused'}
        timestamp={$timestamp}
        bind:seekInputValue
        hidden={loading}
        isLive={$sessionIsLive === true}
        liveActive={$mode === 'live'}
        showSearch={!loading}
        {searchScanning}
        onSearch={runSearch}
        onTogglePlaying={() => player.togglePlaying()}
        onToggleFullscreen={toggleFullscreen}
        onGoLive={() => player.goLive()}
        onSeek={pct => player.scrub($duration * pct / 100)}
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
        flex: 1 0 0;
        min-height: 300px;
    }

    .container {
        padding: 5px;
        margin: auto;
        min-height: 0;
        flex-grow: 1;

        display: flex;
        align-items: center;
    }

    .search-results {
        flex: none;
        max-height: 30%;
        overflow-y: auto;
        background: #1d1d1d;
        border-top: 1px solid #ffffff24;
        font-size: 0.8rem;
        color: #ddd;

        .search-header {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.25rem 0.75rem;
            position: sticky;
            top: 0;
            background: #1d1d1d;
        }

        ul {
            li + li {
                border-top: 1px solid #ffffff12;
            }

            button {
                display: flex;
                align-items: baseline;
                gap: 0.75rem;
                width: 100%;
                text-align: left;
                padding: 0.25rem 0.75rem;
                background: none;
                border: none;
                color: inherit;

                &:hover {
                    background: #ffffff14;
                }
            }
        }

        .match-time {
            flex: none;
            font-size: 0.7rem;
            opacity: .75;
        }

        .match-line {
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            font-family: monospace;

            mark {
                padding: 0;
                background: #8a6d00;
                color: #ffe36e;
            }

            .context {
                opacity: .85;
            }
        }
    }

    :global(.xterm) {
        cursor: pointer !important;
        margin:auto;
    }

    :global(.xterm-viewport) {
        background: none;
    }

    :global(.spinner-border), .pause-overlay {
        appearance: none;
        -webkit-appearance: none;
        background: none;
        border: none;

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
