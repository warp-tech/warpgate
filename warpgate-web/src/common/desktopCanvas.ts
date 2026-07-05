// Shared framebuffer rendering for desktop (RDP/VNC) sessions.
//
// Used by the live in-browser client (gateway/WebDesktop.svelte, synchronous) and the
// admin recording player (admin/player/DesktopRecordingPlayer.svelte, async + ordered so
// image decodes don't race). gen-2 recordings encode framebuffer rects as PNG (`png_image`,
// with `keyframe` full-canvas snapshots); the live interactive client still sends raw BGRA.

export interface Rect {
    x: number
    y: number
    width: number
    height: number
}

// Image payloads arrive base64-encoded from recordings (JSON) and as raw bytes from the
// live binary WebSocket; accept either.
// eslint-disable-next-line @typescript-eslint/no-type-alias
type FrameImageData = string | Uint8Array<ArrayBuffer>

/** The visual subset of desktop messages that mutate the framebuffer. */
export type DesktopFrame =
    | { type: 'resize'; width: number; height: number }
    | { type: 'raw_image'; rect: Rect; data: FrameImageData }
    | {
          type: 'png_image'
          rect: Rect
          keyframe?: boolean
          data: FrameImageData
      }
    | { type: 'jpeg_image'; rect: Rect; data: FrameImageData }
    | { type: 'copy_rect'; dst: Rect; src_x: number; src_y: number }
    | { type: 'cursor'; rect: Rect; data: FrameImageData }

/**
 * A frame that only touches part of the surface and can be dropped to catch up
 * under load. `resize` and full-frame keyframes are structural and never dropped.
 */
export function isIncrementalFrame(msg: DesktopFrame): boolean {
    switch (msg.type) {
        case 'raw_image':
        case 'jpeg_image':
        case 'copy_rect':
        case 'cursor':
            return true
        case 'png_image':
            return !msg.keyframe
        case 'resize':
            return false
    }
}

export function base64ToBytes(b64: string): Uint8Array<ArrayBuffer> {
    const binary = atob(b64)
    const bytes = new Uint8Array(binary.length)
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i)
    }
    return bytes
}

/** Normalize an image payload (base64 from recordings, raw bytes from the live WS). */
function toBytes(data: FrameImageData): Uint8Array<ArrayBuffer> {
    return typeof data === 'string' ? base64ToBytes(data) : data
}

export function ensureCanvasSize(
    canvas: HTMLCanvasElement,
    width: number,
    height: number,
): void {
    if (canvas.width !== width || canvas.height !== height) {
        canvas.width = width
        canvas.height = height
    }
}

function ensureForRect(canvas: HTMLCanvasElement, rect: Rect): void {
    ensureCanvasSize(
        canvas,
        Math.max(canvas.width, rect.x + rect.width),
        Math.max(canvas.height, rect.y + rect.height),
    )
}

function drawRaw(
    ctx: CanvasRenderingContext2D,
    rect: Rect,
    bgra: Uint8Array,
): void {
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
    ctx.putImageData(
        new ImageData(rgba, rect.width, rect.height),
        rect.x,
        rect.y,
    )
}

async function drawImageBlob(
    ctx: CanvasRenderingContext2D,
    rect: Rect,
    bytes: Uint8Array<ArrayBuffer>,
    mime: string,
): Promise<void> {
    const bitmap = await createImageBitmap(new Blob([bytes], { type: mime }))
    ctx.drawImage(bitmap, rect.x, rect.y)
    bitmap.close()
}

/** Apply one framebuffer message. Awaiting the result renders frames strictly in order
 * (recording player: a keyframe must fully paint before the deltas that follow it); the
 * live client fire-and-forgets it (`void`), matching single-frame-at-a-time streaming. */
export async function applyDesktopFrame(
    canvas: HTMLCanvasElement,
    ctx: CanvasRenderingContext2D,
    msg: DesktopFrame,
): Promise<void> {
    switch (msg.type) {
        case 'resize':
            ensureCanvasSize(canvas, msg.width, msg.height)
            break
        case 'raw_image':
            ensureForRect(canvas, msg.rect)
            drawRaw(ctx, msg.rect, toBytes(msg.data))
            break
        case 'png_image':
            ensureForRect(canvas, msg.rect)
            await drawImageBlob(ctx, msg.rect, toBytes(msg.data), 'image/png')
            break
        case 'jpeg_image':
            ensureForRect(canvas, msg.rect)
            await drawImageBlob(ctx, msg.rect, toBytes(msg.data), 'image/jpeg')
            break
        case 'copy_rect':
            ctx.drawImage(
                canvas,
                msg.src_x,
                msg.src_y,
                msg.dst.width,
                msg.dst.height,
                msg.dst.x,
                msg.dst.y,
                msg.dst.width,
                msg.dst.height,
            )
            break
        case 'cursor':
            break
    }
}
