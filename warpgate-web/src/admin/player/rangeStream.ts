// Pulls a recording's ndjson via HTTP Range and hands out one parsed item at a time,
// discarding each as it goes so memory doesn't grow with recording length. Both players
// seek by reopening at the byte offset of an index keyframe and replaying forward from it.
//
// For S3-backed completed recordings the data URL 302-redirects to a presigned URL, which
// the browser follows transparently — Range requests included.
export class RangeStream {
    // Byte offset where the currently open response ends (its Content-Length): the live
    // edge for the next splice. The live WS stream owns everything past it.
    endOffset = 0

    private reader: ReadableStreamDefaultReader<Uint8Array> | null = null
    private lineBuf = ''
    private pending: unknown = null
    private readonly decoder = new TextDecoder()

    constructor(private readonly url: string) {}

    get open(): boolean {
        return this.reader !== null
    }

    abort(): void {
        this.reader?.cancel().catch(() => {})
        this.reader = null
        this.lineBuf = ''
        this.pending = null
    }

    async openAt(offset: number, signal: AbortSignal): Promise<void> {
        this.abort()
        // Pass the seek's signal so a superseded seek aborts this Range request instead of
        // downloading bytes we'll throw away.
        const response = await fetch(this.url, {
            headers: { Range: `bytes=${offset}-` },
            signal,
        })
        // A range starting exactly at the end of the file is not satisfiable (416):
        // that's an empty stream positioned at `offset`, not an error to parse.
        if (!response.ok) {
            this.endOffset = offset
            return
        }
        const contentLength = Number(
            response.headers.get('Content-Length') ?? 0,
        )
        this.endOffset = offset + contentLength
        this.reader = response.body?.getReader() ?? null
    }

    // Next item from the open stream; null at EOF. Unparseable lines are skipped.
    async next<T>(): Promise<T | null> {
        if (this.pending) {
            const item = this.pending as T
            this.pending = null
            return item
        }
        while (this.reader) {
            const nl = this.lineBuf.indexOf('\n')
            if (nl < 0) {
                const { done, value } = await this.reader.read()
                if (done) {
                    const rest = this.lineBuf.trim()
                    this.lineBuf = ''
                    return rest ? parseItem<T>(rest) : null
                }
                this.lineBuf += this.decoder.decode(value, { stream: true })
                continue
            }
            const line = this.lineBuf.slice(0, nl).trim()
            this.lineBuf = this.lineBuf.slice(nl + 1)
            const item = line ? parseItem<T>(line) : null
            if (item) {
                return item
            }
        }
        return null
    }

    // Put back the item that overshot the seek target, so the next pump starts with it.
    push(item: unknown): void {
        this.pending = item
    }
}

function parseItem<T>(line: string): T | null {
    try {
        return JSON.parse(line) as T
    } catch {
        return null
    }
}

export interface Keyframe {
    time: number
    offset: number
}

// The latest seek anchor at or before `time`. Keyframes are in file order.
export function keyframeBefore(keyframes: Keyframe[], time: number): Keyframe {
    let best: Keyframe = { time: 0, offset: 0 }
    for (const kf of keyframes) {
        if (kf.time > time) {
            break
        }
        best = kf
    }
    return best
}
