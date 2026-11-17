export interface SidebarItem {
    title: string
    href: string
}

export const sidebar = $state({
    open: false,
    items: null as SidebarItem[] | null,
    current: null as string | null,
})

export function useSidebar(items: () => SidebarItem[]): void {
    $effect(() => {
        sidebar.items = items() ?? null
        return () => {
            sidebar.items = null
        }
    })
}

export function setCurrentSidebarSubtitle(
    current: () => string | null | undefined,
): void {
    $effect(() => {
        sidebar.current = current() ?? null
        return () => {
            sidebar.current = null
        }
    })
}
