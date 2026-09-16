import type { ActionReturn } from 'svelte/action'

/**
 * Format seconds into a string compatible with the humantime crate
 * e.g., 28800 → "8h", 5400 → "1h 30m", 90 → "1m 30s"
 */
export function formatDurationAsHumantime(totalSeconds: number): string {
    if (totalSeconds <= 0) {
        return '0m'
    }
    const days = Math.floor(totalSeconds / 86400)
    const hours = Math.floor((totalSeconds % 86400) / 3600)
    const minutes = Math.floor((totalSeconds % 3600) / 60)
    const seconds = totalSeconds % 60
    const parts: string[] = []
    if (days) {
        parts.push(`${days}d`)
    }
    if (hours) {
        parts.push(`${hours}h`)
    }
    if (minutes) {
        parts.push(`${minutes}m`)
    }
    if (seconds) {
        parts.push(`${seconds}s`)
    }
    return parts.join(' ') || '0m'
}
/**
 * Parse a humantime crate format duration string into seconds.
 * Accepts: "8h", "1h 30m", "2d", "90m", "1h30m", or plain number (treated as seconds).
 * Returns undefined if the input is empty or unparseable.
 */
export function parseHumantimeDuration(str: string): number | undefined {
    const trimmed = str.trim()
    if (!trimmed) {
        return undefined
    }
    const asNumber = Number(trimmed)
    if (!Number.isNaN(asNumber) && asNumber > 0) {
        return Math.floor(asNumber)
    }
    let total = 0
    let matched = false
    const regex = /(\d+)\s*(d|h|m|s)/gi
    let match: RegExpExecArray | null = null
    // biome-ignore lint/suspicious/noAssignInExpressions: x
    while ((match = regex.exec(trimmed)) !== null) {
        const [, digits, unit] = match
        if (digits && unit) {
            matched = true
            const value = parseInt(digits, 10)
            switch (unit.toLowerCase()) {
                case 'd':
                    total += value * 86400
                    break
                case 'h':
                    total += value * 3600
                    break
                case 'm':
                    total += value * 60
                    break
                case 's':
                    total += value
                    break
            }
        }
    }
    return matched && total > 0 ? total : undefined
}

/**
 * Svelte action for a text input that binds to a seconds value via humantime formatting.
 * Usage: <input use:humantimeDuration={{ seconds: value, onChange: v => { value = v } }} />
 */
export function humantimeDuration(
    node: HTMLInputElement,
    params: {
        seconds: number | undefined
        onChange: (seconds: number | undefined) => void
    },
): ActionReturn {
    node.value =
        params.seconds != null ? formatDurationAsHumantime(params.seconds) : ''

    function handleChange() {
        params.onChange(parseHumantimeDuration(node.value))
    }

    node.addEventListener('change', handleChange)
    return {
        destroy() {
            node.removeEventListener('change', handleChange)
        },
    }
}

export interface DurationUnit {
    label: string
    seconds: number
}

const SECONDS: DurationUnit = { label: 'seconds', seconds: 1 }
const MINUTES: DurationUnit = { label: 'minutes', seconds: 60 }
const HOURS: DurationUnit = { label: 'hours', seconds: MINUTES.seconds * 60 }
const DAYS: DurationUnit = { label: 'days', seconds: HOURS.seconds * 24 }
const WEEKS: DurationUnit = { label: 'weeks', seconds: DAYS.seconds * 7 }

export const DURATION_UNITS: DurationUnit[] = [
    WEEKS,
    DAYS,
    HOURS,
    MINUTES,
    SECONDS,
]

export function bestDurationUnit(
    totalSeconds: number | undefined,
): DurationUnit | undefined {
    if (totalSeconds == null) {
        return MINUTES
    }
    for (const [index, unit] of DURATION_UNITS.entries()) {
        if (totalSeconds % unit.seconds !== 0) {
            continue
        }
        const larger = DURATION_UNITS[index - 1]
        const carry =
            larger &&
            totalSeconds / unit.seconds >= larger.seconds / unit.seconds
        return carry ? undefined : unit
    }
    return undefined
}
