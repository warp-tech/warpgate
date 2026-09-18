/**
 * Tone → colour token and geometry, shared by Callout and ToastHost.
 *
 * Defined once so a warning callout and a warning toast are the same amber
 * diamond, and both match StatusMarker's `pending`. The shapes deliberately
 * reuse StatusMarker's vocabulary:
 *
 *   info     dot       ← the "something is happening" shape, as `live`
 *   success  ring      ← as `online`
 *   warning  diamond   ← as `pending`
 *   danger   triangle  ← as `failed`
 *
 * `blocked` (square) has no tone equivalent: it describes a target's state,
 * not a message about one.
 *
 * Bootstrap's five Alert colours collapse to four here. `secondary` folds
 * into `info` — it was used four times, always for a neutral "working on it"
 * message, and a fifth tone meaning "info but greyer" is one nobody picks
 * correctly.
 */

export type Tone = 'info' | 'success' | 'warning' | 'danger'

export interface ToneSpec {
    token: string
    shape: 'dot' | 'ring' | 'diamond' | 'triangle'
}

export const TONES: Readonly<Record<Tone, Readonly<ToneSpec>>> = Object.freeze({
    info: Object.freeze({ token: '--wg-primary', shape: 'dot' }),
    success: Object.freeze({ token: '--wg-tertiary', shape: 'ring' }),
    warning: Object.freeze({ token: '--wg-secondary', shape: 'diamond' }),
    danger: Object.freeze({ token: '--wg-error', shape: 'triangle' }),
})
