import type { BootstrapThemeColor } from 'gateway/lib/api'

export const VALID_COLORS: BootstrapThemeColor[] = ['Primary', 'Secondary', 'Success', 'Danger', 'Warning', 'Info', 'Light', 'Dark']
export const VALID_CHOICES = ['' as (BootstrapThemeColor | ''), ...VALID_COLORS]
