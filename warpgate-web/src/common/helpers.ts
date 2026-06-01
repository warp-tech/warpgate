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
