/**
 * Admin shell — sidebar, top bar, breadcrumbs and the command palette.
 *
 * Not mounted by the app yet; Phase 4 wires it in behind VITE_NEW_UI.
 */

export { default as AppShell } from './AppShell.svelte'
export type { PaletteAction } from './actions'
export {
    CREATE_ACTIONS,
    NAVIGATION_ACTIONS,
    permittedActions,
} from './actions'
export type { Crumb } from './Breadcrumbs.svelte'
export { default as Breadcrumbs } from './Breadcrumbs.svelte'
export type { PaletteEntity } from './CommandPalette.svelte'
export { default as CommandPalette } from './CommandPalette.svelte'
export { loadPaletteEntities } from './entities'
export { fuzzyMatch, fuzzyRank, highlightRuns } from './fuzzy'
export type { NavItem, NavSection } from './navItems'
export {
    activeItemId,
    NAV_SECTIONS,
    permittedSections,
} from './navItems'
export { default as Sidebar } from './Sidebar.svelte'
export { default as TopBar } from './TopBar.svelte'
