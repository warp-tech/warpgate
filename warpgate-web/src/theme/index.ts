import './tokens.css'
import './fonts.css'

import { get, writable } from 'svelte/store'

type ThemeFileName = 'dark' | 'light'
type ThemeName = ThemeFileName | 'auto'

// Namespaced, like every other key we store (warpgateMenuLocation,
// warpgateWebSSHFontSize, the `warpgate:` prefix in common/autosave.ts).
// HTTP targets are proxied at the portal root, so the portal shares one
// localStorage with every app it proxies, and a bare `theme` collides. Argo CD
// keeps its own `theme` JSON-encoded and JSON.parses it at module scope, so our
// raw 'auto' made JSON.parse throw and its whole bundle died before mounting:
// the proxied UI rendered blank.
const THEME_KEY = 'warpgateTheme'
const savedTheme = (localStorage.getItem(THEME_KEY) ?? 'auto') as ThemeName
export const currentTheme = writable(savedTheme)
export const currentThemeFile = writable<ThemeFileName>('dark')

const styleElement = document.createElement('style')
document.head.appendChild(styleElement)

// tokens.css resolves 'auto' on its own via prefers-color-scheme, so an
// explicit choice is the only thing that needs stamping. Leaving the attribute
// off for 'auto' also means the correct palette paints before this module
// runs, instead of flashing the default and then correcting.
//
// Namespaced `data-wg-theme` rather than `data-theme` for the same reason
// THEME_KEY is namespaced: HTTP targets are proxied at the portal root, and a
// generic attribute name is one more thing that can collide with a proxied
// app's own.
function applyThemeAttribute(theme: ThemeName): void {
    if (theme === 'auto') {
        document.documentElement.removeAttribute('data-wg-theme')
    } else {
        document.documentElement.setAttribute('data-wg-theme', theme)
    }
}

function loadThemeFile(name: ThemeFileName) {
    currentThemeFile.set(name)
    if (name === 'dark') {
        return import('./theme.dark.scss?inline')
    }
    return import('./theme.light.scss?inline')
}

export async function loadTheme(name: ThemeFileName): Promise<void> {
    const theme = (await loadThemeFile(name)).default
    styleElement.innerHTML = theme
}

window
    .matchMedia('(prefers-color-scheme: dark)')
    .addEventListener('change', event => {
        if (get(currentTheme) === 'auto') {
            loadTheme(event.matches ? 'dark' : 'light')
        }
    })

export function setCurrentTheme(theme: ThemeName): void {
    localStorage.setItem(THEME_KEY, theme)
    currentTheme.set(theme)
    applyThemeAttribute(theme)
    if (theme === 'auto') {
        if (window.matchMedia?.('(prefers-color-scheme: dark)').matches) {
            loadTheme('dark')
        } else {
            loadTheme('light')
        }
    } else {
        loadTheme(theme)
    }
}

setCurrentTheme(savedTheme)
