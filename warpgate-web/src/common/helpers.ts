import type { BootstrapThemeColor } from 'gateway/lib/api'

export function getCSSColorFromThemeColor(color?: BootstrapThemeColor): string {
    // Handle capitalized color names from API (e.g., "Primary" -> "primary")
    const colorLower = (color ?? 'Secondary').toLowerCase()
    return `var(--bs-${colorLower});`
}

export function downloadBlob(content: string, filename: string): void {
    const blob = new Blob([content], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
}

type ClassValue =
    | string
    | number
    | boolean
    | null
    | undefined
    | ClassValue[]
    | Record<string, unknown>

export function toClassName(value: ClassValue): string {
    let result = ''

    if (typeof value === 'string' || typeof value === 'number') {
        result += value
    } else if (typeof value === 'object' && value !== null) {
        if (Array.isArray(value)) {
            result = value.map(toClassName).filter(Boolean).join(' ')
        } else {
            for (const key in value) {
                if (value[key]) {
                    if (result) {
                        result += ' '
                    }
                    result += key
                }
            }
        }
    }

    return result
}

export const classnames = (...args: ClassValue[]): string =>
    args.map(toClassName).filter(Boolean).join(' ')

export function uuid(): string {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
        const r = (Math.random() * 16) | 0
        const v = c === 'x' ? r : (r & 0x3) | 0x8
        return v.toString(16)
    })
}
