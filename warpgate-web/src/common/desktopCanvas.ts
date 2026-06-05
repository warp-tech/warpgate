// Shared framebuffer rendering for desktop (RDP/VNC) sessions.
//
// Used by both the live in-browser client (gateway/WebDesktop.svelte) and the
// admin recording player (admin/player/DesktopRecordingPlayer.svelte) so they
// reconstruct the screen identically. The recording on-disk format mirrors the
// live WebSocket `ServerMessage` shape (one timestamped item per line), so the
// same `applyDesktopFrame` drives both.

export interface Rect { x: number, y: number, width: number, height: number }

/** The visual subset of desktop messages that mutate the framebuffer. */
export type DesktopFrame =
    | { type: 'resize', width: number, height: number }
    | { type: 'raw_image', rect: Rect, data: string }
    | { type: 'jpeg_image', rect: Rect, data: string }
    | { type: 'copy_rect', dst: Rect, src_x: number, src_y: number }
    | { type: 'cursor', rect: Rect, data: string }

export function base64ToBytes (b64: string): Uint8Array {
    const binary = atob(b64)
    const bytes = new Uint8Array(binary.length)
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i)
    }
    return bytes
}

export function ensureCanvasSize (canvas: HTMLCanvasElement, width: number, height: number): void {
    if (canvas.width !== width || canvas.height !== height) {
        canvas.width = width
        canvas.height = height
    }
}

function drawRaw (ctx: CanvasRenderingContext2D, rect: Rect, bgra: Uint8Array): void {
    const count = rect.width * rect.height
    const rgba = new Uint8ClampedArray(count * 4)
    for (let i = 0; i < count; i++) {
        const s = i * 4
        // server sends BGRA, canvas wants RGBA
        rgba[s] = bgra[s + 2] ?? 0
        rgba[s + 1] = bgra[s + 1] ?? 0
        rgba[s + 2] = bgra[s] ?? 0
        rgba[s + 3] = 255
    }
    ctx.putImageData(new ImageData(rgba, rect.width, rect.height), rect.x, rect.y)
}

function drawJpeg (ctx: CanvasRenderingContext2D, rect: Rect, bytes: Uint8Array): void {
    const blob = new Blob([bytes], { type: 'image/jpeg' })
    const url = URL.createObjectURL(blob)
    const img = new Image()
    img.onload = () => {
        ctx.drawImage(img, rect.x, rect.y)
        URL.revokeObjectURL(url)
    }
    img.src = url
}

/** Apply one framebuffer message to the canvas. */
export function applyDesktopFrame (
    canvas: HTMLCanvasElement,
    ctx: CanvasRenderingContext2D,
    msg: DesktopFrame,
): void {
    switch (msg.type) {
        case 'resize':
            ensureCanvasSize(canvas, msg.width, msg.height)
            break
        case 'raw_image':
            ensureCanvasSize(
                canvas,
                Math.max(canvas.width, msg.rect.x + msg.rect.width),
                Math.max(canvas.height, msg.rect.y + msg.rect.height),
            )
            drawRaw(ctx, msg.rect, base64ToBytes(msg.data))
            break
        case 'jpeg_image':
            drawJpeg(ctx, msg.rect, base64ToBytes(msg.data))
            break
        case 'copy_rect':
            ctx.drawImage(
                canvas,
                msg.src_x, msg.src_y, msg.dst.width, msg.dst.height,
                msg.dst.x, msg.dst.y, msg.dst.width, msg.dst.height,
            )
            break
        case 'cursor':
            // Cursor overlay not rendered (server-side pointer is rendered into
            // the framebuffer); kept here so the type is exhaustive.
            break
    }
}
