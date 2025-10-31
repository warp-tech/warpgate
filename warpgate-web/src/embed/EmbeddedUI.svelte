<script lang="ts">
import { api } from 'gateway/lib/api'
import { onMount } from 'svelte'
import logo from '../../public/assets/favicon.svg'

let ready = false
let menuVisible = false
let dragging = false
let savedPosition = { x: 0.1, y: 0.8 }
let position = { x: 0.1, y: 0.8 }
let dragStartCoords = { x: 0, y: 0 }
let externalHost: string | undefined = undefined

if (localStorage.warpgateMenuLocation) {
    position = JSON.parse(localStorage.warpgateMenuLocation)
    savedPosition = position
}

onMount(async () => {
    ready = true
    try {
        const info = await api.getInfo()
        externalHost = info.externalHost
    } catch {
        // Ignore errors, fall back to relative URL
    }
})

function drag (e: MouseEvent) {
    if (!dragging) {
        return
    }
    const { x, y } = dragStartCoords
    const { clientX, clientY } = e
    const dx = clientX - x
    const dy = clientY - y
    position = {
        x: Math.max(0, Math.min(1, savedPosition.x + dx / window.innerWidth)),
        y: Math.max(0, Math.min(1, savedPosition.y + dy / window.innerHeight)),
    }
}

function startDragging (e: MouseEvent) {
    dragStartCoords = { x: e.clientX, y: e.clientY }
    dragging = true
}

function stopDragging () {
    dragging = false
    savedPosition = position
    localStorage.warpgateMenuLocation = JSON.stringify(position)
}

function goHome () {
    if (externalHost) {
        // Use the configured external host to ensure we go to the actual warpgate home
        // and not the bound domain home
        location.href = `https://${externalHost}/@warpgate`
    } else {
        // Fallback to relative URL if external host is not available
        location.href = '/@warpgate'
    }
}

async function logout () {
    await api.logout()
    location.reload()
}
</script>

<svelte:window
    on:mousemove|passive={drag}
    on:mouseup={() => {
        menuVisible = false
        stopDragging()
    }}
/>

<div
    class="embedded-ui"
    class:wg-hidden={!ready}
    style="left: {position.x * 100}%; top: {position.y * 100}%"
>
    <!-- svelte-ignore a11y-no-noninteractive-element-interactions -->
    <img
        class="menu-toggle"
        src={logo} alt="Warpgate"
        on:mouseup|stopPropagation|preventDefault={() => {
            if (!dragging) {
                menuVisible = !menuVisible
            } else {
                stopDragging()
            }
        }}
        on:mousedown|preventDefault
        on:mousemove|preventDefault={e => {
            if (e.buttons && !dragging) {
                startDragging(e)
            }
        }}
    >

    {#if menuVisible}
        <div class="menu">
            <button on:mouseup={goHome}>Home</button>
            <button on:mouseup={logout}>Log out</button>
        </div>
    {/if}
</div>

<style lang="scss">
    .embedded-ui {
        position: fixed;
        z-index: 9999;

        color: #555;

        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif, "Apple Color Emoji", "Segoe UI Emoji", "Segoe UI Symbol";

        &.wg-hidden > img.menu-toggle {
            opacity: 0;
        }

        > img.menu-toggle {
            transition: 0.5s ease-out opacity;
            opacity: 1;
            cursor: pointer;

            width: 40px;
            height: 40px;

            border: none;
            padding: 0;
        }

        .menu {
            position: absolute;
            left: 0;
            bottom: calc(100% + 10px);

            min-width: 200px;
            max-height: 50vh;
            overflow-y: auto;

            border-radius: 7px;
            border: 1px solid rgba(128, 128, 128, .25);
            background: rgba(255, 255, 255, .5);
            backdrop-filter: blur(4px);

            padding: 5px;

            > button {
                display: flex;
                align-items: center;
                width: 100%;
                padding: 5px 10px;

                background: transparent;
                border: 0;
                border-radius: 4px;

                color: rgba(0, 0, 0, .5);

                &:not(:first-child) {
                    margin-top: 5px;
                }

                &:hover {
                    color: #555;
                    background: rgba(255, 255, 255, .25);
                }
            }
        }
    }
</style>
