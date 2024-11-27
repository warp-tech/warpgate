import '@fontsource/work-sans'
// import '@fontsource/poppins/800.css'
import './fonts.css'

import { get, writable } from 'svelte/store'

type ThemeFileName = 'dark'|'light'
type ThemeName = ThemeFileName|'auto'

const savedTheme = (localStorage.getItem('theme') ?? 'auto') as ThemeName
export const currentTheme = writable(savedTheme)
export const currentThemeFile = writable<ThemeFileName>('dark')

const styleElement = document.createElement('style')
document.head.appendChild(styleElement)

function loadThemeFile (name: ThemeFileName) {
    currentThemeFile.set(name)
    if (name === 'dark') {
        return import('./theme.dark.scss?inline')
    }
    return import('./theme.light.scss?inline')
}

async function loadTheme (name: ThemeFileName) {
    const theme = (await loadThemeFile(name)).default
    styleElement.innerHTML = theme
}


window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', event => {
    if (get(currentTheme) === 'auto') {
        loadTheme(event.matches ? 'dark' : 'light')
    }
})


export function setCurrentTheme (theme: ThemeName): void {
    localStorage.setItem('theme', theme)
    currentTheme.set(theme)
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
