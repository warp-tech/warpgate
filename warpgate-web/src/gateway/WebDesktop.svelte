<script lang="ts">
    import { onDestroy, onMount } from 'svelte'
    import { Button } from '@sveltestrap/sveltestrap'
    import { api, ResponseError, type WebDesktopSessionInfo } from './lib/api'
    import InfoBox from 'common/InfoBox.svelte'
    import { ReconnectingWebSocket, ConnectionState } from './lib/ReconnectingWebSocket.svelte'
    import { loadTheme } from 'theme'
    import { applyDesktopFrame, type Rect } from 'common/desktopCanvas'

    interface Props {
        params: { sessionId: string }
    }
    let { params }: Props = $props()

    type ServerMessage =
        | { type: 'connection_state'; state: string }
        | { type: 'resize'; width: number; height: number }
        | { type: 'raw_image'; rect: Rect; data: string }
        | { type: 'jpeg_image'; rect: Rect; data: string }
        | { type: 'copy_rect'; dst: Rect; src_x: number; src_y: number }
        | { type: 'cursor'; rect: Rect; data: string }
        | { type: 'clipboard'; text: string }
        | { type: 'bell' }
        | { type: 'error'; message: string }

    // svelte-ignore state_referenced_locally
    const { sessionId } = params

    let canvas: HTMLCanvasElement | undefined = $state()
    let ctx: CanvasRenderingContext2D | null = null
    let connectionError: string | null = $state(null)
    let sessionNotFound = $state(false)
    let sessionInfo = $state<WebDesktopSessionInfo | null>(null)

    const ws = new ReconnectingWebSocket({
        url: `wss://${location.host}/@warpgate/api/web-desktop/sessions/${sessionId}/stream`,
        onOpen: () => null,
        onMessage: data => onMessage(JSON.parse(data) as ServerMessage),
    })

    function send (msg: unknown) {
        ws.send(JSON.stringify(msg))
    }

    function onMessage (msg: ServerMessage) {
        switch (msg.type) {
            case 'connection_state':
                if (msg.state === 'connected') {
                    ws.state = ConnectionState.Connected
                } else if (msg.state === 'disconnected') {
                    ws.state = ConnectionState.Disconnected
                }
                break
            case 'clipboard':
                navigator.clipboard?.writeText(msg.text).catch(() => {})
                break
            case 'bell':
                break
            case 'error':
                ws.state = ConnectionState.Error
                connectionError = msg.message
                break
            default:
                if (ctx && canvas) {
                    void applyDesktopFrame(canvas, ctx, msg)
                }
        }
    }

    // RFB button mask: bit0=left, bit1=middle, bit2=right
    function rfbButtons (e: MouseEvent): number {
        let mask = 0
        if (e.buttons & 1) {
            mask |= 1
        }
        if (e.buttons & 4) {
            mask |= 2
        }
        if (e.buttons & 2) {
            mask |= 4
        }
        return mask
    }

    function canvasCoords (e: MouseEvent): { x: number, y: number } {
        if (!canvas) {
            return { x: 0, y: 0 }
        }
        const r = canvas.getBoundingClientRect()
        const x = Math.round((e.clientX - r.left) * (canvas.width / r.width))
        const y = Math.round((e.clientY - r.top) * (canvas.height / r.height))
        return { x: Math.max(0, x), y: Math.max(0, y) }
    }

    function onPointer (e: MouseEvent) {
        const { x, y } = canvasCoords(e)
        send({ type: 'pointer_event', x, y, buttons: rfbButtons(e) })
    }

    function onWheel (e: WheelEvent) {
        e.preventDefault()
        const { x, y } = canvasCoords(e)
        // delta is a signed notch count: positive = up / right.
        if (e.deltaY !== 0) {
            send({ type: 'wheel_event', x, y, vertical: true, delta: e.deltaY < 0 ? 1 : -1 })
        }
        if (e.deltaX !== 0) {
            send({ type: 'wheel_event', x, y, vertical: false, delta: e.deltaX > 0 ? 1 : -1 })
        }
    }

    // Map a KeyboardEvent to an X11 keysym.
    function keysym (e: KeyboardEvent): number | null {
        const special: Record<string, number> = {
            Backspace: 0xff08,
            Tab: 0xff09,
            Enter: 0xff0d,
            Escape: 0xff1b,
            Delete: 0xffff,
            Home: 0xff50,
            ArrowLeft: 0xff51,
            ArrowUp: 0xff52,
            ArrowRight: 0xff53,
            ArrowDown: 0xff54,
            PageUp: 0xff55,
            PageDown: 0xff56,
            End: 0xff57,
            Insert: 0xff63,
            Shift: 0xffe1,
            Control: 0xffe3,
            Alt: 0xffe9,
            Meta: 0xffeb,
            CapsLock: 0xffe5,
            ' ': 0x0020,
        }
        if (e.key in special) {
            return special[e.key]!
        }
        if (e.key.startsWith('F') && e.key.length <= 3 && !isNaN(Number(e.key.slice(1)))) {
            return 0xffbe + (Number(e.key.slice(1)) - 1) // F1 = 0xffbe
        }
        if (e.key.length === 1) {
            // Latin-1 / ASCII keysyms equal the code point
            return e.key.charCodeAt(0)
        }
        return null
    }

    function onKey (e: KeyboardEvent, down: boolean) {
        const ks = keysym(e)
        if (ks === null) {
            return
        }
        e.preventDefault()
        send({ type: 'key_event', keysym: ks, down })
    }

    async function disconnect () {
        ws.close()
        try {
            await api.deleteWebDesktopSession({ sessionId })
        } catch {
            // ignore
        }
        window.close()
    }

    onMount(async () => {
        if (canvas) {
            ctx = canvas.getContext('2d')
        }
        try {
            sessionInfo = await api.getWebDesktopSession({ sessionId })
        } catch (e) {
            connectionError = e instanceof Error ? e.message : 'Failed to load session info'
            if (e instanceof ResponseError && e.response.status === 404) {
                sessionNotFound = true
            }
            return
        }
        ws.connect()
    })

    onDestroy(() => {
        ws.close()
    })

    loadTheme('dark')
</script>

<svelte:window
    onkeydown={e => onKey(e, true)}
    onkeyup={e => onKey(e, false)}
/>

<div class="desktop-web-client d-flex flex-column">
    <div class="toolbar d-flex align-items-center gap-2 p-2">
        <span class="me-auto text-muted small">{sessionInfo?.targetName ?? ''}</span>
        {#if !sessionNotFound}
            <span class="text-muted small me-3">
                {ws.state}{#if ws.state === ConnectionState.Connecting && ws.attempt > 0}&nbsp;(attempt {ws.attempt}){/if}
            </span>
        {/if}
        <Button color="danger" size="sm" onclick={disconnect}>Disconnect</Button>
    </div>

    {#if connectionError}
        <div class="mx-3 mt-3">
            <InfoBox variant="warning">
                {#if sessionNotFound}
                    Session not found. It may have expired or been closed.
                {:else}
                    {connectionError}
                {/if}
            </InfoBox>
        </div>
    {/if}

    <div class="canvas-area flex-grow-1 d-flex align-items-center justify-content-center">
        <canvas
            bind:this={canvas}
            tabindex="0"
            onmousemove={onPointer}
            onmousedown={onPointer}
            onmouseup={onPointer}
            onwheel={onWheel}
            oncontextmenu={e => e.preventDefault()}
        ></canvas>
    </div>
</div>

<style lang="scss">
    :global(body) {
        margin: 0;
        overflow: hidden;
    }

    .desktop-web-client {
        height: 100vh;
        background: black;
    }

    .toolbar {
        flex-shrink: 0;
        margin: 10px;
        background: black;
        border-radius: 10px;
    }

    .canvas-area {
        overflow: auto;
    }

    canvas {
        image-rendering: pixelated;
        max-width: 100%;
        max-height: 100%;
        outline: none;
    }
</style>
