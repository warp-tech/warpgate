/**
 * NET-NEW primitive (store half).
 *
 * Toast queue. Nothing in the existing UI does this — today, results are
 * reported with inline sveltestrap Alerts, which is why AsyncButton had to
 * grow a done/failed state of its own.
 *
 * Design notes that matter for an ops tool:
 *   - errors do NOT auto-dismiss. A failed "close session" that vanishes
 *     after four seconds while the operator was looking at the target list is
 *     an incident waiting to happen.
 *   - the queue is capped. A retry loop firing a toast per attempt must not
 *     bury the screen; the oldest non-error toast is evicted first.
 *   - dedupe by key, so ten identical failures are one toast with a count
 *     rather than ten stacked copies.
 */

export type ToastTone = 'info' | 'success' | 'warning' | 'error'

export interface Toast {
    id: number
    tone: ToastTone
    title: string
    detail?: string
    /** ms; 0 or absent means it stays until dismissed. */
    duration?: number
    /** Identical keys collapse into one toast with a repeat count. */
    key?: string
    count: number
    action?: { label: string; run: () => void }
}

const MAX_VISIBLE = 4
const DEFAULT_DURATION: Record<ToastTone, number> = {
    info: 4000,
    success: 4000,
    warning: 8000,
    error: 0, // sticky — see above
}

let nextId = 1

class ToastQueue {
    items = $state<Toast[]>([])
    #timers = new Map<number, ReturnType<typeof setTimeout>>()

    push(
        tone: ToastTone,
        title: string,
        options: {
            detail?: string
            duration?: number
            key?: string
            action?: { label: string; run: () => void }
        } = {},
    ): number {
        const key = options.key ?? `${tone}:${title}`
        const existing = this.items.find(t => t.key === key)
        if (existing) {
            existing.count += 1
            this.#arm(existing)
            return existing.id
        }

        const toast: Toast = {
            id: nextId++,
            tone,
            title,
            detail: options.detail,
            duration: options.duration ?? DEFAULT_DURATION[tone],
            key,
            count: 1,
            action: options.action,
        }

        this.items = [...this.items, toast]
        this.#evict()
        this.#arm(toast)
        return toast.id
    }

    // Errors are never evicted to make room; if the cap is reached and every
    // toast is an error, the new one is still added rather than dropped —
    // losing an error silently is the one outcome worse than a crowded corner.
    #evict() {
        while (this.items.length > MAX_VISIBLE) {
            const victim =
                this.items.find(t => t.tone !== 'error') ?? this.items[0]
            if (!victim) {
                return
            }
            this.dismiss(victim.id)
        }
    }

    #arm(toast: Toast) {
        const existing = this.#timers.get(toast.id)
        if (existing) {
            clearTimeout(existing)
            this.#timers.delete(toast.id)
        }
        if (!toast.duration) {
            return
        }
        this.#timers.set(
            toast.id,
            setTimeout(() => this.dismiss(toast.id), toast.duration),
        )
    }

    /** Pauses auto-dismiss — called when the stack is hovered or focused. */
    hold(id: number) {
        const timer = this.#timers.get(id)
        if (timer) {
            clearTimeout(timer)
            this.#timers.delete(id)
        }
    }

    resume(id: number) {
        const toast = this.items.find(t => t.id === id)
        if (toast) {
            this.#arm(toast)
        }
    }

    dismiss(id: number) {
        this.hold(id)
        this.items = this.items.filter(t => t.id !== id)
    }

    clear() {
        for (const timer of this.#timers.values()) {
            clearTimeout(timer)
        }
        this.#timers.clear()
        this.items = []
    }
}

export const toasts = new ToastQueue()

export const toast = {
    info: (title: string, o?: Parameters<ToastQueue['push']>[2]) =>
        toasts.push('info', title, o),
    success: (title: string, o?: Parameters<ToastQueue['push']>[2]) =>
        toasts.push('success', title, o),
    warning: (title: string, o?: Parameters<ToastQueue['push']>[2]) =>
        toasts.push('warning', title, o),
    error: (title: string, o?: Parameters<ToastQueue['push']>[2]) =>
        toasts.push('error', title, o),
}
