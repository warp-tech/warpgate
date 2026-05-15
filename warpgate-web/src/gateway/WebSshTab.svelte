<script lang="ts" module>
    export const THEME = {
        foreground: '#cacaca',
        background: '#171717',
        cursor: '#bbbbbb',
        colors: [
            '#000000',
            '#ff615a',
            '#b1e969',
            '#ebd99c',
            '#5da9f6',
            '#e86aff',
            '#82fff7',
            '#dedacf',
            '#313131',
            '#f58c80',
            '#ddf88f',
            '#eee5b2',
            '#a5c7ff',
            '#ddaaff',
            '#b7fff9',
            '#ffffff',
        ],
    }
</script>
<script lang="ts">
    import { onDestroy } from 'svelte'
    import { Terminal } from '@xterm/xterm'
    import { FitAddon } from '@xterm/addon-fit'
    import { Unicode11Addon } from '@xterm/addon-unicode11'

    interface Props {
        active: boolean
        fontSize: number
        readOnly: boolean
        onInput: (data: string) => void
        onResize: (cols: number, rows: number) => void
        onTitleChange: (title: string) => void
    }

    let { active, fontSize, readOnly, onInput, onResize, onTitleChange }: Props = $props()

    const terminal = new Terminal({
        allowProposedApi: true,
        cursorBlink: true,
        theme: {
            foreground: THEME.foreground,
            background: THEME.background,
            cursor: THEME.cursor,
            black: THEME.colors[0],
            red: THEME.colors[1],
            green: THEME.colors[2],
            yellow: THEME.colors[3],
            blue: THEME.colors[4],
            magenta: THEME.colors[5],
            cyan: THEME.colors[6],
            white: THEME.colors[7],
            brightBlack: THEME.colors[8],
            brightRed: THEME.colors[9],
            brightGreen: THEME.colors[10],
            brightYellow: THEME.colors[11],
            brightBlue: THEME.colors[12],
            brightMagenta: THEME.colors[13],
            brightCyan: THEME.colors[14],
            brightWhite: THEME.colors[15],
        },
        fontFamily: 'monospace-fallback, monospace',
    })

    const fitAddon = new FitAddon()
    terminal.loadAddon(fitAddon)
    terminal.onData(data => onInput(data))
    terminal.onTitleChange(t => onTitleChange(t))
    terminal.loadAddon(new Unicode11Addon())
    terminal.unicode.activeVersion = '11'

    $effect(() => {
        terminal.options.fontSize = fontSize
        fitAddon.fit()
        onResize(terminal.cols, terminal.rows)
    })

    $effect(() => {
        terminal.options.disableStdin = readOnly
    })

    export function write (data: string | Uint8Array): void {
        terminal.write(data)
    }

    export function fit (): void {
        fitAddon.fit()
        onResize(terminal.cols, terminal.rows)
    }

    export function getSize (): { cols: number; rows: number } {
        return { cols: terminal.cols, rows: terminal.rows }
    }

    function mountTerminal (el: HTMLDivElement) {
        terminal.open(el)
        requestAnimationFrame(() => {
            fitAddon.fit()
            onResize(terminal.cols, terminal.rows)
        })
        return { destroy () {} }
    }

    onDestroy(() => {
        terminal.dispose()
    })
</script>

<div
    class="position-absolute top-0 start-0 w-100 h-100"
    class:d-none={!active}
    use:mountTerminal
></div>

<style lang="scss">
    @import "../../node_modules/@xterm/xterm/css/xterm.css";

    :global(.xterm) {
        height: 100%;
        padding: 7px 10px;
    }

    :global(.xterm-viewport) {
        overflow-y: hidden !important;
        background: transparent !important;
    }
</style>
