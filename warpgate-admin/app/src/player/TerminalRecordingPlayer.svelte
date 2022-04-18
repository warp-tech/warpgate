<script lang="ts">
    import Fa from 'svelte-fa'
    import { onDestroy, onMount } from 'svelte'
    import { Terminal } from 'xterm'
    import { SerializeAddon } from 'xterm-addon-serialize'
    import { faPlay, faPause, faExpand } from '@fortawesome/free-solid-svg-icons'
    import { Spinner } from 'sveltestrap'
    import formatDuration from 'format-duration'

    export let url: string

    let containerElement: HTMLDivElement
    let rootElement: HTMLDivElement
    let timestamp = 0
    let seekInputValue = 0
    let duration = 0
    let resizeObserver: ResizeObserver
    let events: (SizeEvent | DataEvent | SnapshotEvent)[] = []
    let playing = false
    let loading = true

    const COLOR_NAMES = [
        'black', 'red', 'green', 'yellow', 'blue', 'magenta', 'cyan', 'white',
        'brightBlack', 'brightRed', 'brightGreen', 'brightYellow', 'brightBlue', 'brightMagenta', 'brightCyan', 'brightWhite',
    ]

    const theme = {
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
        theme[COLOR_NAMES[i]] = colors[i]
    }

    interface SizeEvent { time: number, cols: number, rows: number }
    interface DataEvent { time: number, data: string }
    interface SnapshotEvent { time: number, snapshot: string }

    const term = new Terminal()
    const serializeAddon = new SerializeAddon()

    onMount(async () => {
        term.loadAddon(serializeAddon)
        term.open(containerElement)

        term.options.theme = theme
        term.options.scrollback = 0

        fitSize()
        resizeObserver = new ResizeObserver(fitSize)
        resizeObserver.observe(containerElement)

        const data = await fetch(url).then(r => r.text())
        for (const line of data.split('\n')) {
            addData(JSON.parse(line))
        }

        await seek(duration)
        await seek(0)
        loading = false
    })

    function addData (data) {
        if (data.version) {
            duration = Math.max(duration, data.time)
            events.push({
                time: data.time,
                cols: data.width,
                rows: data.height,
            })
        }
        if (data instanceof Array) {
            duration = Math.max(duration, data[0])
            events.push({
                time: data[0],
                data: data[2],
            })
        }
    }

    let metricsCanvas: HTMLCanvasElement
    function fitSize () {
        metricsCanvas ??= document.createElement('canvas')
        const context = metricsCanvas.getContext('2d')!
        context.font = '10px ' + term.options.fontFamily ?? 'monospace'
        const metrics = context.measureText('abcdef')

        const fontWidth = containerElement.clientWidth / term.cols
        term.options.fontSize = fontWidth / (metrics.width / 6) * 10
    }

    let seekPromise = Promise.resolve()

    async function seek (time) {
        seekPromise = seekPromise.then(() => _seekInternal(time))
        await seekPromise
    }

    async function _seekInternal (time) {
        let nearestSnapshot: SnapshotEvent|null = null

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
            index = Math.max(index, events.findIndex(e => e.time > timestamp))
        }
        let lastSize = { cols: term.cols, rows: term.rows }

        for (let i = 0; i <= index; i++) {
            let event = events[i]
            if ('cols' in event) {
                lastSize = { cols: event.cols, rows: event.rows }
            }
        }

        resize(lastSize.cols, lastSize.rows)

        let output = ''

        async function flush () {
            await new Promise<void>(r => {
                term.write(output, r)
            })
            output = ''
        }

        for (let i = index; i < events.length; i++) {
            let shouldSnapshot = false
            let event = events[i]
            if (event.time > time) {
                break
            }
            if ('snapshot' in event) {
                output += '\x1bc' + event.snapshot
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
        seekInputValue = 100 * time / duration
    }

    function resize (cols, rows) {
        if (term.cols === cols && term.rows === rows) {
            return
        }
        term.resize(cols, rows)
        fitSize()
    }

    onDestroy(() => resizeObserver?.disconnect())

    let destroyed = false
    onDestroy(() => destroyed = true)

    async function step () {
        if (destroyed) {
            return
        }
        if (playing) {
            await seek(timestamp + 0.1)
        }
        setTimeout(step, 100)
    }

    function togglePlaying () {
        playing = !playing
    }

    step()

    function toggleFullscreen () {
        if (document.fullscreenElement) {
            document.exitFullscreen()
        } else {
            rootElement.requestFullscreen()
        }
    }
</script>

<div class="root" bind:this={rootElement} style="background: {theme.background}">
    {#if loading}
    <Spinner color="primary" />
    {/if}

    {#if !loading && !playing}
    <div class="pause-overlay">
        <Fa icon={faPlay} size="2x" fw />
    </div>
    {/if}

    <div
    class="container"
    class:invisible={loading}
    on:click={togglePlaying}
    bind:this={containerElement}
    ></div>

    <div class="toolbar" class:invisible={loading}>
        <button class="btn btn-link" on:click={togglePlaying}>
            <Fa icon={playing ? faPause : faPlay} fw />
        </button>
        <pre class="timestamp">{ formatDuration(timestamp * 1000, { leading: true }) }</pre>
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
    @import "../../node_modules/xterm/css/xterm.css";

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

    .toolbar {
        display: flex;
    }

    :global(.xterm) {
        cursor: pointer !important;
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

    input[type="range"] {
        -webkit-appearance: none;
        margin: 18px 10px 0;
        height: 2px;
        background: #ffffff99;
        border-radius: 5px;
        background: linear-gradient(#eee, #eee);
        background-repeat: no-repeat;
        cursor: pointer;

        &:hover::-webkit-slider-thumb {
            transform: scale(1.5);
        }
    }

    input[type="range"]::-webkit-slider-thumb {
        -webkit-appearance: none;
        height: 10px;
        width: 10px;
        border-radius: 50%;
        background: #eee;
        transition: all .25s ease-out;
    }

    input[type=range]::-webkit-slider-runnable-track  {
        -webkit-appearance: none;
        box-shadow: none;
        border: none;
        background: transparent;
    }

    .timestamp {
        flex: none;
        overflow: visible;
        color: #eeeeee;
        font-size: 0.75rem;
        margin: 0;
        align-self: center;
    }
</style>
