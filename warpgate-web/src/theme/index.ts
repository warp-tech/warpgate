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

function resolve(theme: ThemeName): ThemeFileName {
    if (theme !== 'auto') {
        return theme
    }
    return window.matchMedia?.('(prefers-color-scheme: dark)').matches
        ? 'dark'
        : 'light'
}

/**
 * Kept as a function, but it no longer loads anything.
 *
 * This used to `import('./theme.dark.scss?inline')` and inject the result into
 * a <style> element — two compiled Bootstrap builds, 356 KB of JavaScript
 * between them, one of which was fetched at runtime on every theme change.
 * The token layer in tokens.css now carries both palettes and switches on the
 * `data-wg-theme` attribute, so there is nothing left to fetch.
 *
 * It survives as a named export because the in-browser SSH and desktop clients
 * call it on mount: those routes render outside the app shells, and the call
 * is what guarantees `currentThemeFile` reflects the resolved theme for
 * Brand.svelte's per-theme SVG. Making it a no-op that still updates that
 * store keeps both call sites correct without touching the clients.
 */
export async function loadTheme(name: ThemeFileName): Promise<void> {
    currentThemeFile.set(name)
}

window
    .matchMedia('(prefers-color-scheme: dark)')
    .addEventListener('change', event => {
        if (get(currentTheme) === 'auto') {
            currentThemeFile.set(event.matches ? 'dark' : 'light')
        }
    })

export function setCurrentTheme(theme: ThemeName): void {
    localStorage.setItem(THEME_KEY, theme)
    currentTheme.set(theme)
    applyThemeAttribute(theme)
    currentThemeFile.set(resolve(theme))
}

setCurrentTheme(savedTheme)
