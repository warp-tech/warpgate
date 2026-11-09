<script lang="ts">
    import { logoUrl } from 'common/helpers'
    import { serverInfo } from 'gateway/lib/store'
    import { onDestroy } from 'svelte'
    import { get } from 'svelte/store'
    import { currentThemeFile } from 'theme'
    import logo from '../../public/assets/brand.svg?raw'

    let element: HTMLElement | undefined = $state()

    let s = currentThemeFile.subscribe(colorizeByTheme)

    function colorize(
        r: number,
        g: number,
        b: number,
        dr: number,
        dg: number,
        db: number,
    ) {
        element?.querySelectorAll('path').forEach((p, idx) => {
            let d = idx
            p.style.fill = `rgb(${r + d * dr}, ${g + d * dg}, ${b + d * db})`
        })
    }

    function colorizeByTheme() {
        if (get(currentThemeFile) === 'light') {
            colorize(49, 57, 72, -1, 1, 3)
        } else {
            colorize(203, 212, 235, -3, -2, -1)
        }
    }

    $effect(() => {
        // react to logo changes
        if (element) {
            colorizeByTheme()
        }
    })

    onDestroy(s)
</script>

{#if $serverInfo?.logoEtag}
    <img class="custom-logo" src={logoUrl($serverInfo.logoEtag)} alt="Logo">
{:else}
    <div bind:this={element} class="brand">
        {@html logo}
    </div>
{/if}

<style lang="scss">
    :global(svg) {
        width: auto;
        display: block;
        max-height: 100%;
    }

    .brand {
        height: 22px;
    }

    // fixed height and max width + object-fit prefer max height while keepng aspect ratio
    .custom-logo {
        display: block;
        height: 32px;
        width: auto;
        max-width: 200px;
        object-fit: contain;
        object-position: left center;
    }
</style>
