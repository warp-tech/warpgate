import { type BootstrapThemeColor } from 'gateway/lib/api'

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

// eslint-disable-next-line @typescript-eslint/explicit-module-boundary-types
export function toClassName(value: any) {
    let result = ''

    if (typeof value === 'string' || typeof value === 'number') {
        result += value
    } else if (typeof value === 'object') {
        if (Array.isArray(value)) {
            result = value.map(toClassName).filter(Boolean).join(' ')
        } else {
            for (const key in value) {
                if (value[key]) {
                    // eslint-disable-next-line @typescript-eslint/no-unused-expressions
                    result && (result += ' ')
                    result += key
                }
            }
        }
    }

    return result
}

// eslint-disable-next-line @typescript-eslint/explicit-module-boundary-types
export const classnames = (...args: any[]) =>
    args.map(toClassName).filter(Boolean).join(' ')

export function uuid(): string {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
        const r = (Math.random() * 16) | 0
        const v = c === 'x' ? r : (r & 0x3) | 0x8
        return v.toString(16)
    })
}
