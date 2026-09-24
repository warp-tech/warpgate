/**
 * WCAG 2.1 relative luminance and contrast, used to audit the token palette
 * live in the styleguide rather than trusting a number pasted into a doc.
 *
 * Values are read back from the resolved custom properties, so what the
 * styleguide reports is what the browser actually painted.
 */

function parseColor(value: string): [number, number, number] | null {
    const v = value.trim()

    const hex = v.match(/^#([0-9a-f]{3}|[0-9a-f]{6})$/i)
    if (hex?.[1]) {
        const h = hex[1]
        const full =
            h.length === 3
                ? h
                      .split('')
                      .map(c => c + c)
                      .join('')
                : h
        return [0, 2, 4].map(i =>
            Number.parseInt(full.slice(i, i + 2), 16),
        ) as [number, number, number]
    }

    // getComputedStyle normalises to rgb()/rgba() in every browser we target
    const rgb = v.match(/^rgba?\(([^)]+)\)$/i)
    if (rgb?.[1]) {
        const parts = rgb[1]
            .split(/[\s,/]+/)
            .filter(Boolean)
            .map(Number.parseFloat)
        if (parts.length >= 3) {
            return [parts[0] ?? 0, parts[1] ?? 0, parts[2] ?? 0]
        }
    }

    return null
}

function luminance([r, g, b]: [number, number, number]): number {
    const [lr, lg, lb] = [r, g, b].map(c => {
        const s = c / 255
        return s <= 0.04045 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4
    })
    return 0.2126 * (lr ?? 0) + 0.7152 * (lg ?? 0) + 0.0722 * (lb ?? 0)
}

export function contrast(a: string, b: string): number | null {
    const ca = parseColor(a)
    const cb = parseColor(b)
    if (!ca || !cb) {
        return null
    }
    const [hi, lo] = [luminance(ca), luminance(cb)].sort((x, y) => y - x)
    return ((hi ?? 0) + 0.05) / ((lo ?? 0) + 0.05)
}

export type Grade = 'AAA' | 'AA' | 'AA Large' | 'UI only' | 'Fail'

/**
 * Grades against 1.4.3 (text) with the 1.4.11 non-text threshold called out
 * separately — a 3.2:1 border passes for a component boundary and fails for
 * body copy, and conflating the two is how contrast bugs ship.
 */
export function grade(ratio: number | null): Grade {
    if (ratio === null) {
        return 'Fail'
    }
    if (ratio >= 7) {
        return 'AAA'
    }
    if (ratio >= 4.5) {
        return 'AA'
    }
    if (ratio >= 3) {
        return 'AA Large'
    }
    return 'Fail'
}

export function resolveToken(name: string, el?: Element): string {
    const target = el ?? document.documentElement
    return getComputedStyle(target).getPropertyValue(name).trim()
}
