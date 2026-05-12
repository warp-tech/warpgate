/**
 * Format seconds into a string compatible with the humantime crate
 * e.g., 28800 → "8h", 5400 → "1h 30m", 90 → "1m 30s"
 */
export function formatDurationAsHumantime (totalSeconds: number): string {
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
    if (seconds && !days && !hours) {
        parts.push(`${seconds}s`)
    }
    return parts.join(' ') || '0m'
}

/**
 * Parse a humantime crate format duration string into seconds.
 * Accepts: "8h", "1h 30m", "2d", "90m", "1h30m", or plain number (treated as seconds).
 * Returns undefined if the input is empty or unparseable.
 */
export function parseHumantimeDuration (str: string): number | undefined {
    const trimmed = str.trim()
    if (!trimmed) {
        return undefined
    }
    const asNumber = Number(trimmed)
    if (!isNaN(asNumber) && asNumber > 0) {return Math.floor(asNumber)}
    let total = 0
    let matched = false
    const regex = /(\d+)\s*(d|h|m|s)/gi
    let match
    while ((match = regex.exec(trimmed)) !== null) {
        matched = true
        const value = parseInt(match[1]!)
        switch (match[2]!.toLowerCase()) {
            case 'd': total += value * 86400; break
            case 'h': total += value * 3600; break
            case 'm': total += value * 60; break
            case 's': total += value; break
        }
    }
    return matched && total > 0 ? total : undefined
}
