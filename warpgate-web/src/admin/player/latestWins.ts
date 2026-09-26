// Runs async tasks one at a time, "latest wins": starting a new run supersedes any
// still-queued run (only the most recent pending arg ever executes) and aborts the running
// task's `AbortSignal`, so the task can bail early — and, because it's a standard signal,
// abort in-flight `fetch`es (e.g. a superseded seek's HTTP Range request) for free.
//
// This is the cancel + coalesce + serialize pattern the players kept hand-rolling for
// seeking. Extracted so the terminal and desktop players share one implementation.
export function latestWins<T>(
    task: (arg: T, signal: AbortSignal) => Promise<void>,
): (arg: T) => void {
    let draining = false
    let queued: { arg: T } | null = null
    let current: AbortController | null = null

    async function drain(): Promise<void> {
        draining = true
        try {
            while (queued) {
                const { arg } = queued
                queued = null
                current = new AbortController()
                const { signal } = current
                try {
                    await task(arg, signal)
                } catch (err) {
                    // An AbortError just means this run was superseded (its fetch / body
                    // stream was cancelled) — expected, not a failure. `signal.aborted` can
                    // still read false when the abort arrives via `reader.cancel()`, so also
                    // match by name.
                    const aborted =
                        signal.aborted ||
                        (err instanceof Error && err.name === 'AbortError')
                    if (!aborted) {
                        console.error('latestWins task failed', err)
                    }
                }
            }
        } finally {
            current = null
            draining = false
        }
    }

    return function run(arg: T): void {
        current?.abort() // supersede any in-flight task (its signal is now aborted)
        queued = { arg } // …and coalesce: only this newest arg will run next
        if (!draining) {
            void drain()
        }
    }
}
