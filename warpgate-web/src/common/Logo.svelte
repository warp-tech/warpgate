<script type="ts">
import { onDestroy, onMount } from 'svelte'
import { get } from 'svelte/store'
import { currentThemeFile } from 'theme'
import logo from '../../public/assets/logo.svg?raw'

let element: HTMLElement|undefined

function colorize (r: number, g: number, b: number, dr: number, dg: number, db: number) {
    element?.querySelectorAll('path').forEach((p, idx) => {
        let d = idx
        p.style.fill = `rgb(${r + d * dr}, ${g + d * dg}, ${b + d * db})`
    })
}

function colorizeByTheme () {
    if (get(currentThemeFile) === 'light') {
        colorize(81, 47, 185, -1, 1, 3)
    } else {
        colorize(131, 167, 255, -3, 1, -1)
    }
}

let s = currentThemeFile.subscribe(colorizeByTheme)

onMount(() => {
    colorizeByTheme()
})

onDestroy(s)

</script>

<div bind:this={element} class="d-flex">
    {@html logo}
</div>

<style>
    :global(svg) {
        width: 100%;
    }
</style>
