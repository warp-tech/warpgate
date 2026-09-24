<script lang="ts">
    /**
     * Cycles auto -> dark -> light -> auto.
     *
     * Behaviour preserved exactly, including the cycle order. The tooltip
     * becomes ui/Tooltip and the button keeps a real accessible name that
     * states the CURRENT theme — the sveltestrap version had a static
     * "Switch theme" title and put the actual state only in a hover tooltip.
     */
    import { get } from 'svelte/store'
    import { currentTheme, setCurrentTheme } from 'theme'
    import Button from 'ui/Button.svelte'
    import Tooltip from 'ui/Tooltip.svelte'

    function toggle() {
        const t = get(currentTheme)
        if (t === 'auto') {
            setCurrentTheme('dark')
        } else if (t === 'dark') {
            setCurrentTheme('light')
        } else {
            setCurrentTheme('auto')
        }
    }

    const label = $derived(
        $currentTheme === 'dark'
            ? 'Dark theme'
            : $currentTheme === 'light'
              ? 'Light theme'
              : 'Automatic theme',
    )
</script>

<Tooltip text="{label} — click to change" placement="left">
    <Button variant="ghost" size="compact" {label} onclick={toggle}>
        {#if $currentTheme === 'dark'}
            <svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true">
                <path
                    d="M13 9.5A5.5 5.5 0 0 1 6.5 3a5.5 5.5 0 1 0 6.5 6.5z"
                    fill="currentColor"
                />
            </svg>
        {:else if $currentTheme === 'light'}
            <svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true">
                <circle cx="8" cy="8" r="3" fill="currentColor" />
                <path
                    d="M8 1v2M8 13v2M15 8h-2M3 8H1M12.9 3.1l-1.4 1.4M4.5 11.5l-1.4 1.4M12.9 12.9l-1.4-1.4M4.5 4.5L3.1 3.1"
                    stroke="currentColor"
                    stroke-width="1.4"
                    stroke-linecap="round"
                />
            </svg>
        {:else}
            <svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true">
                <circle
                    cx="6.5"
                    cy="7"
                    r="2.5"
                    fill="none"
                    stroke="currentColor"
                    stroke-width="1.4"
                />
                <path
                    d="M11 12.5a2.75 2.75 0 0 0 0-5.5 3.75 3.75 0 0 0-7.2.9A2.6 2.6 0 0 0 4.2 12.5z"
                    fill="none"
                    stroke="currentColor"
                    stroke-width="1.4"
                    stroke-linejoin="round"
                />
            </svg>
        {/if}
    </Button>
</Tooltip>
