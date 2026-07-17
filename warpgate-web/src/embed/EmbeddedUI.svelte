<script lang="ts">
    import { api } from 'gateway/lib/api'
    import { onMount } from 'svelte'
    import logo from '../../public/assets/favicon.svg'

    // Movement in pixels before a press turns into a drag rather than a menu toggle.
    const DRAG_THRESHOLD = 5

    let ready = false
    let menuVisible = false
    let dragging = false
    let savedPosition = { x: 0.1, y: 0.8 }
    let position = { x: 0.1, y: 0.8 }
    let dragStartCoords: { x: number; y: number } | undefined
    let externalHost: string | undefined

    if (localStorage.warpgateMenuLocation) {
        position = JSON.parse(localStorage.warpgateMenuLocation)
        savedPosition = position
    }

    onMount(async () => {
        ready = true
        const info = await api.getInfo()
        externalHost = `${info.externalHosts?.http ?? info.externalHost}:${info.ports.http ?? 443}`
    })

    function startDragging(e: PointerEvent) {
        dragStartCoords = { x: e.clientX, y: e.clientY }
        dragging = false
        // Capture guarantees the matching pointerup/pointermove reach the icon even
        // if the pointer leaves the window, so a release outside can't strand `dragging`.
        ;(e.currentTarget as Element).setPointerCapture(e.pointerId)
    }

    function drag(e: PointerEvent) {
        if (!dragStartCoords) {
            return
        }
        const dx = e.clientX - dragStartCoords.x
        const dy = e.clientY - dragStartCoords.y
        if (!dragging && Math.hypot(dx, dy) < DRAG_THRESHOLD) {
            return
        }
        dragging = true
        position = {
            x: Math.max(
                0,
                Math.min(1, savedPosition.x + dx / window.innerWidth),
            ),
            y: Math.max(
                0,
                Math.min(1, savedPosition.y + dy / window.innerHeight),
            ),
        }
    }

    function endDragging() {
        if (dragging) {
            savedPosition = position
            localStorage.warpgateMenuLocation = JSON.stringify(position)
        }
        dragStartCoords = undefined
    }

    function goHome() {
        if (externalHost) {
            location.href = `https://${externalHost}/@warpgate`
        } else {
            location.href = '/@warpgate'
        }
    }

    async function logout() {
        await api.logout()
        location.reload()
    }
</script>

<svelte:window on:pointerup={() => (menuVisible = false)} />

<div
    class="embedded-ui"
    class:wg-hidden={!ready}
    style="left: {position.x * 100}%; top: {position.y * 100}%"
>
    <!-- svelte-ignore a11y-no-noninteractive-element-interactions -->
    <img
        class="menu-toggle"
        src={logo}
        alt="Warpgate"
        on:pointerdown|preventDefault={startDragging}
        on:pointermove={drag}
        on:pointerup|stopPropagation|preventDefault={() => {
            if (!dragging) {
                menuVisible = !menuVisible
            }
            endDragging()
        }}
        on:pointercancel={endDragging}
    >

    {#if menuVisible}
        <div class="menu">
            <button type="button" on:pointerup={goHome}>Home</button>
            <button type="button" on:pointerup={logout}>Log out</button>
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
