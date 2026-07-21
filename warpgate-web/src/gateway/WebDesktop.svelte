<script lang="ts">
    import { faCompress, faExpand } from '@fortawesome/free-solid-svg-icons'
    import { Button } from '@sveltestrap/sveltestrap'
    import {
        applyDesktopFrame,
        type DesktopFrame,
        isIncrementalFrame,
        type Rect,
    } from 'common/desktopCanvas'
    import InfoBox from 'common/InfoBox.svelte'
    import { onDestroy, onMount } from 'svelte'
    import Fa from 'svelte-fa'
    import { loadTheme } from 'theme'
    import { api, ResponseError, type WebDesktopSessionInfo } from './lib/api'
    import {
        ConnectionState,
        ReconnectingWebSocket,
    } from './lib/ReconnectingWebSocket.svelte'

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
    // Gates the fade-in; set on the first painted batch.
    let painted = $state(false)
    // The whole client goes fullscreen, not just the canvas, so the toolbar (and the
    // disconnect button) stays reachable.
    let rootElement: HTMLDivElement | undefined = $state()
    let isFullscreen = $state(false)
    let ctx: CanvasRenderingContext2D | null = null
    let connectionError: string | null = $state(null)
    let sessionNotFound = $state(false)
    let sessionInfo = $state<WebDesktopSessionInfo | null>(null)

    // Framebuffer messages are queued off the WS thread and painted in a rAF loop so a
    // burst of updates (e.g. dragging a window) can never block the main thread. Beyond
    // this cap we drop the oldest incremental frames to stay near the live edge.
    const MAX_PENDING_FRAMES = 360
    let pendingFrames: DesktopFrame[] = []
    let rafHandle: number | null = null
    // Latest pointer position, flushed at most once per frame (mousemove fires far faster
    // than we need to forward); button presses/releases are sent immediately.
    let pendingPointer: { x: number; y: number; buttons: number } | null = null

    const ws = new ReconnectingWebSocket({
        url: `wss://${location.host}/@warpgate/api/web-desktop/sessions/${sessionId}/stream`,
        onOpen: () => null,
        onMessage: onWsMessage,
    })

    function send(msg: unknown) {
        ws.send(JSON.stringify(msg))
    }

    // Pixel frames arrive as binary (see the backend's `ws_payload`); control messages
    // (connection state, resize, copy-rect, clipboard, error) arrive as JSON text.
    function onWsMessage(data: string | ArrayBuffer) {
        if (typeof data !== 'string') {
            const frame = decodeBinaryFrame(data)
            if (frame) {
                queueFrame(frame)
            }
            return
        }
        const msg = JSON.parse(data) as ServerMessage
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
                queueFrame(msg)
        }
    }

    // `[kind: u8][x,y,w,h: u16 LE][pixels…]` — the compact binary framing sent for pixels.
    function decodeBinaryFrame(buf: ArrayBuffer): DesktopFrame | null {
        if (buf.byteLength < 9) {
            return null
        }
        const view = new DataView(buf)
        const rect = {
            x: view.getUint16(1, true),
            y: view.getUint16(3, true),
            width: view.getUint16(5, true),
            height: view.getUint16(7, true),
        }
        const data = new Uint8Array(buf, 9)
        switch (view.getUint8(0)) {
            case 1:
                return { type: 'raw_image', rect, data }
            case 2:
                return { type: 'jpeg_image', rect, data }
            case 3:
                return { type: 'cursor', rect, data }
            case 4:
                // Full-canvas base image sent on attach; never shed from the queue.
                return { type: 'png_image', rect, data, keyframe: true }
            case 5:
                // Lossless resend of a region that stopped changing.
                return { type: 'png_image', rect, data }
            default:
                return null
        }
    }

    // Queue a framebuffer message for the next paint. When we fall behind, shed the
    // oldest droppable frame so the backlog (and per-frame work) stays bounded; structural
    // frames (resize / keyframes) are kept.
    function queueFrame(frame: DesktopFrame) {
        pendingFrames.push(frame)
        if (pendingFrames.length > MAX_PENDING_FRAMES) {
            const idx = pendingFrames.findIndex(isIncrementalFrame)
            pendingFrames.splice(idx === -1 ? 0 : idx, 1)
        }
    }

    // Single rAF loop: paint whatever has arrived, then forward the latest pointer.
    function tick() {
        if (ctx && canvas && pendingFrames.length) {
            const batch = pendingFrames
            pendingFrames = []
            for (const frame of batch) {
                void applyDesktopFrame(canvas, ctx, frame)
            }
            // Reveal only once there's something to show, so the canvas fades in with the
            // first real content instead of flashing an empty surface.
            painted = true
        }
        if (pendingPointer) {
            send({ type: 'pointer_event', ...pendingPointer })
            pendingPointer = null
        }
        rafHandle = requestAnimationFrame(tick)
    }

    function toggleFullscreen() {
        if (document.fullscreenElement) {
            void document.exitFullscreen()
        } else {
            void rootElement?.requestFullscreen()
        }
    }

    // RFB button mask: bit0=left, bit1=middle, bit2=right
    function rfbButtons(e: MouseEvent): number {
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

    function canvasCoords(e: MouseEvent): { x: number; y: number } {
        if (!canvas) {
            return { x: 0, y: 0 }
        }
        const r = canvas.getBoundingClientRect()
        const x = Math.round((e.clientX - r.left) * (canvas.width / r.width))
        const y = Math.round((e.clientY - r.top) * (canvas.height / r.height))
        return { x: Math.max(0, x), y: Math.max(0, y) }
    }

    // Coalesce high-frequency moves: keep only the latest, forwarded once per frame by `tick`.
    function onPointerMove(e: MouseEvent) {
        const { x, y } = canvasCoords(e)
        pendingPointer = { x, y, buttons: rfbButtons(e) }
    }

    // Button transitions must not be delayed or coalesced away, so send them immediately.
    function onPointerButton(e: MouseEvent) {
        const { x, y } = canvasCoords(e)
        pendingPointer = null
        send({ type: 'pointer_event', x, y, buttons: rfbButtons(e) })
    }

    function onWheel(e: WheelEvent) {
        e.preventDefault()
        const { x, y } = canvasCoords(e)
        // delta is a signed notch count: positive = up / right.
        if (e.deltaY !== 0) {
            send({
                type: 'wheel_event',
                x,
                y,
                vertical: true,
                delta: e.deltaY < 0 ? 1 : -1,
            })
        }
        if (e.deltaX !== 0) {
            send({
                type: 'wheel_event',
                x,
                y,
                vertical: false,
                delta: e.deltaX > 0 ? 1 : -1,
            })
        }
    }

    // Map a KeyboardEvent to an X11 keysym.
    function keysym(e: KeyboardEvent): number | null {
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
        const specialKey = special[e.key]
        if (specialKey) {
            return specialKey
        }
        if (
            e.key.startsWith('F') &&
            e.key.length <= 3 &&
            !Number.isNaN(Number(e.key.slice(1)))
        ) {
            return 0xffbe + (Number(e.key.slice(1)) - 1) // F1 = 0xffbe
        }
        if (e.key.length === 1) {
            // Latin-1 / ASCII keysyms equal the code point
            return e.key.charCodeAt(0)
        }
        return null
    }

    function onKey(e: KeyboardEvent, down: boolean) {
        const ks = keysym(e)
        if (ks === null) {
            return
        }
        e.preventDefault()
        send({ type: 'key_event', keysym: ks, down })
    }

    async function disconnect() {
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
        rafHandle = requestAnimationFrame(tick)
        try {
            sessionInfo = await api.getWebDesktopSession({ sessionId })
        } catch (e) {
            connectionError =
                e instanceof Error ? e.message : 'Failed to load session info'
            if (e instanceof ResponseError && e.response.status === 404) {
                sessionNotFound = true
            }
            return
        }
        ws.connect()
    })

    onDestroy(() => {
        ws.close()
        if (rafHandle !== null) {
            cancelAnimationFrame(rafHandle)
        }
    })

    loadTheme('dark')
</script>

<svelte:window onkeydown={e => onKey(e, true)} onkeyup={e => onKey(e, false)} />
<!-- Tracked via the event rather than a local toggle, so leaving fullscreen with Esc
     (which fires no click) still updates the button. -->
<svelte:document
    onfullscreenchange={() => (isFullscreen = !!document.fullscreenElement)}
/>

<div class="desktop-web-client d-flex flex-column" bind:this={rootElement}>
    <div class="toolbar d-flex align-items-center gap-2 p-2">
        <span class="me-auto text-muted small"
            >{sessionInfo?.targetName ?? ''}</span
        >
        {#if !sessionNotFound}
            <span class="text-muted small me-3">
                {ws.state}
                {#if ws.state === ConnectionState.Connecting && ws.attempt > 0}
                    &nbsp;(attempt {ws.attempt})
                {/if}
            </span>
        {/if}
        <button
            type="button"
            class="btn btn-link"
            title={isFullscreen ? 'Exit fullscreen' : 'Fullscreen'}
            onclick={toggleFullscreen}
        >
            <Fa icon={isFullscreen ? faCompress : faExpand} fw />
        </button>
        <Button color="danger" size="sm" onclick={disconnect}
            >Disconnect</Button
        >
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

    <div
        class="canvas-area flex-grow-1 d-flex align-items-center justify-content-center"
    >
        <canvas
            bind:this={canvas}
            class:painted
            tabindex="0"
            onmousemove={onPointerMove}
            onmousedown={onPointerButton}
            onmouseup={onPointerButton}
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

        // Hidden until the first frame is painted, so the desktop eases in instead of
        // snapping from a blank surface.
        opacity: 0;
        transition: opacity 0.5s ease-in-out;

        &.painted {
            opacity: 1;
        }
    }
</style>
