<script lang="ts">
    import Fa from 'svelte-fa'
    import { faCloudSun, faMoon, faSun } from '@fortawesome/free-solid-svg-icons'
    import { Button } from '@sveltestrap/sveltestrap'
    import { get } from 'svelte/store'

    import { currentTheme, setCurrentTheme } from 'theme'
    import Tooltip from './sveltestrap-s5-ports/Tooltip.svelte'

    function toggle () {
        if (get(currentTheme) === 'auto') {
            setCurrentTheme('dark')
        } else if (get(currentTheme) === 'dark') {
            setCurrentTheme('light')
        } else {
            setCurrentTheme('auto')
        }
    }
</script>

<Button color="link" on:click={toggle} id="button" title="Switch theme">
    {#if $currentTheme === 'dark'}
    <Fa fw icon={faMoon} />
    {:else if $currentTheme === 'light'}
    <Fa fw icon={faSun} />
    {:else}
    <Fa fw icon={faCloudSun} />
    {/if}
</Button>
<Tooltip target="button" animation>
    {#if $currentTheme === 'dark'}
    Dark theme
    {:else if $currentTheme === 'light'}
    Light theme
    {:else}
    Automatic theme
    {/if}
</Tooltip>
