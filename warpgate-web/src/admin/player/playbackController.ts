import { LiveRecordingStream } from 'common/liveRecordingStream'
import { writable } from 'svelte/store'
import { latestWins } from './latestWins'
import { type Keyframe, keyframeBefore, RangeStream } from './rangeStream'

// Playback modes. `live` tails the growing recording (items applied as they stream);
// `playing` advances through recorded time; `paused` holds the current picture. Grabbing
// the scrubber pauses; "go live" enters `live`; play/pause toggles paused↔playing and
// always leaves `live`.
export type PlayerMode = 'paused' | 'playing' | 'live'

// How often playback advances, and by how much.
const STEP_INTERVAL_MS = 100
const STEP_S = 0.1

interface TimedItem {
    time: number
}

// What a player has to supply: how to paint. Everything about *when* — seeking, keyframe
// anchoring, playback stepping, live tailing — belongs to the controller.
export interface PlaybackRenderer<T extends TimedItem> {
    // Return to an empty picture, about to replay forward from `kf`. Called after the byte
    // stream reopens at the anchor, before its items arrive.
    reset(kf: Keyframe): void | Promise<void>
    // Apply one item read from the file. May buffer; `flush` ends the batch.
    apply(item: T): void | Promise<void>
    // Apply one live item arriving past the snapshot edge.
    applyLive(item: T): void | Promise<void>
    // Paint whatever `apply` buffered. Always called at the end of a replay batch,
    // including when the batch was superseded — dropping buffered items would leave the
    // picture missing bytes that the next seek may not replay.
    flush?(): void | Promise<void>
}

interface SeekRequest {
    time: number
    keyframeSkip: boolean
    goLive: boolean
}

// Drives a recording player: seeks by reopening the byte stream at the nearest index
// keyframe and replaying forward, steps through recorded time, and tails the live edge.
// Observable state is exposed as stores so components stay in sync without plumbing.
export class PlaybackController<T extends TimedItem> {
    readonly mode = writable<PlayerMode>('paused')
    readonly timestamp = writable(0)
    readonly duration = writable(0)
    // Scrubber position, 0..100.
    readonly seekPercent = writable(0)
    // null until the live stream reports; true while the session is still running.
    readonly sessionIsLive = writable<boolean | null>(null)

    private readonly data: RangeStream
    private stream: LiveRecordingStream | null = null
    private keyframes: Keyframe[] = []
    // How far the picture has actually been replayed, which trails the requested seek time
    // until the pump catches up. Drives the decision to reopen instead of continuing.
    private renderedTime = 0
    private destroyed = false

    private currentMode: PlayerMode = 'paused'
    private currentTimestamp = 0
    private currentDuration = 0

    constructor(
        private readonly urls: { data: string; stream: string },
        private readonly renderer: PlaybackRenderer<T>,
    ) {
        this.data = new RangeStream(urls.data)
    }

    // Seek anchors and total duration, parsed from the recording's index by the player
    // (the index entries differ per protocol).
    setIndex(keyframes: Keyframe[], duration: number): void {
        this.keyframes = keyframes
        this.currentDuration = duration
        this.publish()
    }

    // Paint the first picture, awaited so a player can hold its spinner until there is
    // something to see. Nothing else is seeking yet, so the signal is never aborted.
    async paintInitial(time = 0): Promise<void> {
        await this.doSeek(
            { time, keyframeSkip: false, goLive: false },
            new AbortController().signal,
        )
    }

    // Subscribe to the live stream and start the playback stepper.
    start(): void {
        this.stream = new LiveRecordingStream(this.urls.stream, {
            onStart: live => {
                this.sessionIsLive.set(live)
                if (live) {
                    this.goLive()
                }
            },
            onEnd: () => {
                this.sessionIsLive.set(false)
                if (this.currentMode === 'live') {
                    this.currentMode = 'paused'
                    this.publish()
                }
            },
            // Only the duration high-water mark needs every item (it's idempotent).
            // Rendering must NOT go here — it would double count items the file already
            // contributes through the pump.
            tap: item => {
                const time = (item as T).time
                if (typeof time === 'number' && time > this.currentDuration) {
                    this.currentDuration = time
                    this.publish()
                }
            },
            onNext: async item => {
                await this.renderer.applyLive(item as T)
                this.renderedTime = (item as T).time
                this.currentTimestamp = this.renderedTime
                this.publish()
            },
        })
        this.step()
    }

    destroy(): void {
        this.destroyed = true
        this.data.abort()
        this.stream?.close()
    }

    seek(time: number, keyframeSkip = false, goLive = false): void {
        this.runSeek({
            time: Math.max(0, Math.min(this.currentDuration, time)),
            keyframeSkip,
            goLive,
        })
    }

    // Grabbing the scrubber pauses and leaves live (so live items don't fight the scrub).
    scrub(time: number): void {
        this.stream?.pause()
        this.currentMode = 'paused'
        this.publish()
        this.seek(time, true)
    }

    togglePlaying(): void {
        // Play/pause always leaves live tailing (pausing freezes the current picture).
        this.stream?.pause()
        this.currentMode = this.currentMode === 'paused' ? 'playing' : 'paused'
        this.publish()
    }

    // Jump to the live edge: a keyframe-based seek to the newest recorded item, then tail.
    // Held paused during the rebase so playback stepping and live applies don't interfere;
    // `doSeek` flips to `live` once the correct picture is painted.
    goLive(): void {
        this.currentMode = 'paused'
        this.publish()
        // Retain live items from now; `doSeek` splices them at the rebased edge.
        this.stream?.arm()
        this.seek(this.currentDuration, true, true)
    }

    // All seeks go through one latest-wins runner: rapid scrubs coalesce and a new seek
    // supersedes any in-flight one. `keyframeSkip` lets an explicit scrub jump forward to a
    // keyframe; playback stepping leaves it off so it replays every intermediate item.
    private readonly runSeek = latestWins((req: SeekRequest, signal) =>
        this.doSeek(req, signal),
    )

    private async doSeek(req: SeekRequest, signal: AbortSignal) {
        const { time, keyframeSkip, goLive } = req
        // Restart the stream at the keyframe ≤ time when we can't cheaply continue forward:
        // no open stream, seeking backward, or (on an explicit scrub) a keyframe lies
        // between our replay position and the target — jumping beats replaying the items.
        const kf = keyframeBefore(this.keyframes, time)
        if (
            !this.data.open ||
            time < this.renderedTime ||
            (keyframeSkip && kf.time > this.renderedTime)
        ) {
            await this.data.openAt(kf.offset, signal)
            if (signal.aborted) {
                return
            }
            await this.renderer.reset(kf)
            if (signal.aborted) {
                return
            }
            this.renderedTime = kf.time
        }
        // A go-live seek pumps to the end of the data, not just to `time`: the known
        // duration lags the file tail by up to a keyframe interval, and splice() drops
        // every buffered live item the byte range already covers — anything left
        // unpainted here would be missing from the picture for good.
        const eof = await this.pumpUntil(goLive ? Infinity : time, signal)
        if (signal.aborted) {
            return
        }
        if (goLive) {
            // The drained response reflects the file as of when it was opened, which can
            // be stale (a stream left open across a pause). Catch up on growth since then
            // by continuing from its end offset; the WS buffer (armed before this seek)
            // owns everything past the continuation's own edge.
            await this.data.openAt(this.data.endOffset, signal)
            await this.pumpUntil(Infinity, signal)
            if (signal.aborted) {
                return
            }
        }
        this.currentTimestamp = goLive
            ? Math.max(time, this.renderedTime)
            : time
        this.currentDuration = Math.max(
            this.currentDuration,
            this.currentTimestamp,
        )
        this.publish()
        // Playback drained the file while the session is still running: it has caught up
        // with the recording, so switch to tailing rather than stepping the timestamp
        // onward over a frozen picture (the file has no further items yet).
        if (
            eof &&
            !goLive &&
            this.currentMode === 'playing' &&
            this.stream?.live
        ) {
            this.goLive()
            return
        }
        // The picture now reflects the file up to the live edge, so it's finally safe to
        // tail: applying live items onto a stale picture is what corrupted it.
        if (goLive) {
            await this.stream?.splice(this.data.endOffset)
            this.currentMode = 'live'
            this.publish()
        }
    }

    // Replay the stream up to `time`, unless a newer seek supersedes us. Returns whether
    // the file ran out before `time` was reached.
    private async pumpUntil(
        time: number,
        signal: AbortSignal,
    ): Promise<boolean> {
        try {
            for (;;) {
                const item = await this.data.next<T>()
                if (signal.aborted) {
                    return false
                }
                if (!item) {
                    return true
                }
                if (item.time > time) {
                    this.data.push(item)
                    return false
                }
                await this.renderer.apply(item)
                if (signal.aborted) {
                    return false
                }
                this.renderedTime = item.time
            }
        } finally {
            await this.renderer.flush?.()
        }
    }

    private step = () => {
        if (this.destroyed) {
            return
        }
        if (
            this.currentMode === 'playing' &&
            this.currentTimestamp < this.currentDuration
        ) {
            this.seek(
                Math.min(this.currentDuration, this.currentTimestamp + STEP_S),
            )
        }
        setTimeout(this.step, STEP_INTERVAL_MS)
    }

    private publish() {
        this.mode.set(this.currentMode)
        this.timestamp.set(this.currentTimestamp)
        this.duration.set(this.currentDuration)
        this.seekPercent.set(
            this.currentDuration
                ? (100 * this.currentTimestamp) / this.currentDuration
                : 0,
        )
    }
}
