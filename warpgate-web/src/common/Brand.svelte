<script lang="ts">
    import { onDestroy, onMount } from 'svelte'
    import logo from '../../public/assets/brand.svg?raw'
    import { currentThemeFile } from 'theme'
    import { get } from 'svelte/store'

    let element: HTMLElement|undefined = $state()

    let s = currentThemeFile.subscribe(colorizeByTheme)

    function colorize (r: number, g: number, b: number, dr: number, dg: number, db: number) {
        element?.querySelectorAll('path').forEach((p, idx) => {
            let d = idx
            p.style.fill = `rgb(${r + d * dr}, ${g + d * dg}, ${b + d * db})`
        })
    }

    function colorizeByTheme () {
        if (get(currentThemeFile) === 'light') {
            colorize(49, 57, 72, -1, 1, 3)
        } else {
            colorize(203, 212, 235, -3, -2, -1)
        }
    }

    onMount(() => {
        colorizeByTheme()
    })

onDestroy(s)
</script>


<div bind:this={element} class="brand">
    <!-- eslint-disable-next-line svelte/no-at-html-tags -->
    {@html logo}
</div>


<style lang="scss">
    :global(svg) {
        width: auto;
        display: block;
        max-height: 100%;
    }

    .brand {
        height: 22px;
    }
</style>
