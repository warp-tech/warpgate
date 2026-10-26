// Shared framebuffer rendering for desktop (RDP/VNC) sessions.
//
// Used by the live in-browser client (gateway/WebDesktop.svelte) and the admin recording
// player (admin/player/DesktopRecordingPlayer.svelte). Both paint strictly in arrival
// order; the live client additionally starts each image decode as the frame arrives, so a
// burst still decodes in parallel. gen-2 recordings encode framebuffer rects as PNG
// (`png_image`, with `keyframe` full-canvas snapshots); the live stream mixes raw BGRA
// tiles with the JPEG/PNG the backend re-encodes larger ones to.

export interface Rect {
    x: number
    y: number
    width: number
    height: number
}

// Image payloads arrive base64-encoded from recordings (JSON) and as raw bytes from the
// live binary WebSocket; accept either.
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
    // `rect.x`/`rect.y` are the hotspot; empty `data` hides the cursor.
    | { type: 'cursor'; rect: Rect; data: FrameImageData }
    | { type: 'cursor_default' }
    | { type: 'cursor_hidden' }

/** A frame whose image decode, if it has one, is already running. */
export type PreparedFrame = DesktopFrame & {
    bitmap?: Promise<ImageBitmap | null>
}

// Exhaustive over DesktopFrame['type'], so adding a frame kind fails compilation here
// instead of leaving a hand-kept list stale.
const FRAME_TYPES: Record<DesktopFrame['type'], true> = {
    resize: true,
    raw_image: true,
    png_image: true,
    jpeg_image: true,
    copy_rect: true,
    cursor: true,
    cursor_default: true,
    cursor_hidden: true,
}

/** Whether a stream item type is a framebuffer frame, as opposed to a viewer-input item. */
export function isDesktopFrameType(type: string): type is DesktopFrame['type'] {
    return Object.hasOwn(FRAME_TYPES, type)
}

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
        case 'cursor_default':
        case 'cursor_hidden':
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

// The server sends BGRA, the canvas wants RGBA. Framebuffer tiles are opaque; only a
// cursor sprite carries a meaningful alpha channel.
function bgraToImageData(
    bgra: Uint8Array,
    width: number,
    height: number,
    keepAlpha: boolean,
): ImageData {
    const count = width * height
    const rgba = new Uint8ClampedArray(count * 4)
    for (let i = 0; i < count; i++) {
        const s = i * 4
        rgba[s] = bgra[s + 2] ?? 0
        rgba[s + 1] = bgra[s + 1] ?? 0
        rgba[s + 2] = bgra[s] ?? 0
        rgba[s + 3] = keepAlpha ? (bgra[s + 3] ?? 0) : 255
    }
    return new ImageData(rgba, width, height)
}

function drawRaw(
    ctx: CanvasRenderingContext2D,
    rect: Rect,
    bgra: Uint8Array,
): void {
    ctx.putImageData(
        bgraToImageData(bgra, rect.width, rect.height, false),
        rect.x,
        rect.y,
    )
}

// A cursor sprite as a CSS `cursor` value. Browsers cap custom cursors (128px in Chromium,
// less elsewhere) and silently fall back to the keyword after the comma.
function cursorCss(rect: Rect, bgra: Uint8Array): string {
    if (rect.width === 0 || rect.height === 0 || bgra.length === 0) {
        return 'none'
    }
    const sprite = document.createElement('canvas')
    sprite.width = rect.width
    sprite.height = rect.height
    sprite
        .getContext('2d')
        ?.putImageData(
            bgraToImageData(bgra, rect.width, rect.height, true),
            0,
            0,
        )
    return `url(${sprite.toDataURL()}) ${rect.x} ${rect.y}, auto`
}

function decodeBlob(
    data: FrameImageData,
    mime: string,
): Promise<ImageBitmap | null> {
    // A decode that fails resolves to `null`: dropping one tile beats wedging the paint
    // loop waiting on it, and beats an unhandled rejection surfacing frames later.
    return createImageBitmap(new Blob([toBytes(data)], { type: mime })).catch(
        () => null,
    )
}

function startDecode(
    msg: DesktopFrame,
): Promise<ImageBitmap | null> | undefined {
    switch (msg.type) {
        case 'png_image':
            return decodeBlob(msg.data, 'image/png')
        case 'jpeg_image':
            return decodeBlob(msg.data, 'image/jpeg')
        default:
            return undefined
    }
}

/**
 * Start a frame's image decode ahead of painting it, so a queued burst decodes in
 * parallel while still being painted in arrival order.
 */
export function decodeDesktopFrame(msg: DesktopFrame): PreparedFrame {
    const bitmap = startDecode(msg)
    return bitmap ? { ...msg, bitmap } : msg
}

// Serializes paints per canvas: `createImageBitmap` does not resolve in issue order on
// every engine — Chromium resolves roughly by completion time, so a large tile lands
// after the small ones queued behind it — and painting as decodes land would leave stale
// pixels on top of newer ones, permanently, until that region is repainted again.
const paintChains = new WeakMap<HTMLCanvasElement, Promise<void>>()

/**
 * Apply one framebuffer message. Frames for the same canvas paint strictly in call
 * order, even if the caller doesn't await; awaiting is only needed for completion or
 * backpressure.
 */
export function applyDesktopFrame(
    canvas: HTMLCanvasElement,
    ctx: CanvasRenderingContext2D,
    msg: PreparedFrame,
): Promise<void> {
    const previous = paintChains.get(canvas) ?? Promise.resolve()
    const result = previous.then(() => paintFrame(canvas, ctx, msg))
    // The stored tail swallows the failure so one bad frame can't wedge every later
    // one; the caller still sees its own frame's rejection.
    paintChains.set(
        canvas,
        result.catch(() => undefined),
    )
    return result
}

async function paintFrame(
    canvas: HTMLCanvasElement,
    ctx: CanvasRenderingContext2D,
    msg: PreparedFrame,
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
        case 'jpeg_image': {
            const bitmap = await (msg.bitmap ?? startDecode(msg))
            if (bitmap) {
                // Growing the canvas clears it, so grow only once there are pixels to put
                // back — never for a decode that turned out to be unusable.
                ensureForRect(canvas, msg.rect)
                ctx.drawImage(bitmap, msg.rect.x, msg.rect.y)
                bitmap.close()
            }
            break
        }
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
            canvas.style.cursor = cursorCss(msg.rect, toBytes(msg.data))
            break
        case 'cursor_default':
            canvas.style.cursor = ''
            break
        case 'cursor_hidden':
            canvas.style.cursor = 'none'
            break
        default:
            // Compile-time exhaustiveness: a new frame kind must be handled above.
            return msg satisfies never
    }
}
