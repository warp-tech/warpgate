import { TargetKind, type BootstrapThemeColor, type TargetSnapshot } from 'gateway/lib/api'

export function getCSSColorFromThemeColor(color?: BootstrapThemeColor): string {
    // Handle capitalized color names from API (e.g., "Primary" -> "primary")
    const colorLower = (color ?? 'Secondary').toLowerCase()
    return `var(--bs-${colorLower});`
}
