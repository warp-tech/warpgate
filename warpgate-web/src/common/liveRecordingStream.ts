// Gap-free live streaming logic for players
//
// * Subscribe to live stream and buffer
// * Load the existing snapshot
// * Drop live events already in the snapshot and emit the rest
// * Continue receiving live events

type LiveStreamMessage =
    | {
          type: 'start'
          live: boolean
      }
    | {
          type: 'data'
          data: unknown
          offset: number
      }
    | {
          type: 'end'
      }

export interface LiveRecordingStreamOptions {
    // A new valid message arrived, whether from snapshot or live
    // Returning a promise serializes calls
    onNext: (item: unknown, offset: number) => void | Promise<void>
    onStart?: (live: boolean) => void
    onEnd?: () => void
    // Called for every item in arrival order, before dedup
    tap?: (item: unknown, offset: number) => void
}

export class LiveRecordingStream {
    live: boolean | null = null

    private readonly socket: WebSocket
    private buffer: { offset: number; item: unknown }[] = []

    // retain items ahead of a splice
    private armed = false
    // apply live items directly
    private tailing = false
    // high-water byte offset already applied or in the snapshot
    private edge = 0

    constructor(
        url: string,
        private readonly options: LiveRecordingStreamOptions,
    ) {
        this.socket = new WebSocket(url)
        this.socket.addEventListener('message', event => {
            this.handle(JSON.parse(event.data) as LiveStreamMessage)
        })
        this.socket.addEventListener('close', () =>
            console.info('Live stream closed'),
        )
    }

    // Start retaining live items ahead of a splice
    arm(): void {
        this.armed = true
    }

    // Activates the stream after snapshot with the first `boundary` bytes is loaded,
    // applies buffered items past `boundary`, then tails subsequent items.
    async splice(boundary: number): Promise<void> {
        this.edge = Math.max(this.edge, boundary)
        // Stay armed through the (possibly async) applies so items arriving
        // mid-flush are retained and drained here rather than dropped
        while (this.buffer.length) {
            const next = this.buffer.shift()
            if (next && next.offset > this.edge) {
                this.edge = next.offset
                await this.options.onNext(next.item, next.offset)
            }
        }
        this.tailing = true
        this.armed = false
    }

    // Stop tailing and drop the buffer; the next splice re-reads from storage.
    pause(): void {
        this.tailing = false
        this.armed = false
        this.buffer = []
    }

    close(): void {
        this.socket.close()
    }

    private handle(message: LiveStreamMessage): void {
        if (message.type === 'start') {
            this.live = Boolean(message.live)
            this.options.onStart?.(this.live)
        }
        if (message.type === 'data') {
            const offset = message.offset
            const item = message.data
            this.options.tap?.(item, offset)
            if (this.tailing) {
                if (offset > this.edge) {
                    this.edge = offset
                    void this.options.onNext(item, offset)
                }
            } else if (this.armed) {
                this.buffer.push({ offset, item })
            }
        }
        if (message.type === 'end') {
            this.live = false
            this.options.onEnd?.()
        }
    }
}
