<script lang="ts">
    import {
        faCircle,
        faExpand,
        faFastForward,
        faPause,
        faPlay,
    } from '@fortawesome/free-solid-svg-icons'
    import { Tooltip } from '@sveltestrap/sveltestrap'
    import formatDuration from 'format-duration'
    import Fa from 'svelte-fa'

    // Shared controls for the recording players (terminal + desktop): play/pause,
    // elapsed time, optional LIVE button, a scrubber with an optional input-density
    // heatmap, and fullscreen. The parent owns the actual seek/playback logic and passes
    // it in, so protocol-specific behaviour (e.g. keyframe-aware desktop seeks) stays out
    // of here.
    export let playing: boolean
    export let timestamp: number
    export let seekInputValue: number
    export let hidden = false
    // Show the LIVE button; `liveActive` highlights it when tailing the live edge.
    export let isLive = false
    export let liveActive = false
    // Optional per-bucket (0..1) input-density band drawn behind the scrubber.
    export let heatmap: number[] | null = null
    export let onTogglePlaying: () => void
    export let onToggleFullscreen: () => void
    export let onGoLive: () => void
    // Called with the new scrubber position as a percentage (0..100).
    export let onSeek: (percent: number) => void
</script>

<div class="toolbar" class:invisible={hidden}>
    <button type="button" class="btn btn-link" on:click={onTogglePlaying}>
        <Fa icon={playing ? faPause : faPlay} fw />
    </button>
    <pre
        class="timestamp"
    >{ formatDuration(timestamp * 1000, { leading: true }) }</pre>
    {#if isLive}
        {#if liveActive}
            <div class="live-indicator gap-2 m-2">
                <Fa icon={faCircle} size="xs" />
                <span>Live</span>
            </div>
        {:else}
            <button
                type="button"
                id="go-live-button"
                class="btn btn-link text-danger d-flex align-items-center gap-2"
                on:click={onGoLive}
            >
                <Fa icon={faFastForward} size="xs" />
            </button>
            <Tooltip target="go-live-button" placement="top" container="body">
                Go live
            </Tooltip>
        {/if}
    {/if}
    <div class="seek">
        {#if heatmap}
            <div class="heatmap" aria-hidden="true">
                {#each heatmap as v, i (i)}
                    <span style="opacity: {v}"></span>
                {/each}
            </div>
        {/if}
        <input
            class="w-100"
            type="range"
            min="0"
            max="100"
            step="0.001"
            style="background-size: {seekInputValue}% 100%;"
            bind:value={seekInputValue}
            on:input={() => onSeek(seekInputValue)}
        >
    </div>
    <button type="button" class="btn btn-link" on:click={onToggleFullscreen}>
        <Fa icon={faExpand} fw />
    </button>
</div>

<style lang="scss">
    .toolbar {
        display: flex;
        height: 45px;
    }

    .btn {
        color: #eee;

        :global(svg) {
            transition: all .25s ease-out;
        }

        &:hover :global(svg) {
            transform: scale(1.2);
        }
    }

    .timestamp {
        flex: none;
        overflow: visible;
        color: #eeeeee;
        margin: 0;
        font-size: 0.75rem;
        align-self: center;
    }

    .live-indicator {
        display: flex;
        align-items: center;
        color: red;

        span {
            text-transform: uppercase;
            font-weight: bold;
            font-size: 0.75rem;
            letter-spacing: 1px;
        }
    }

    .seek {
        position: relative;
        flex: 1 1 auto;
        display: grid;
        margin: 0 10px;
    }

    .heatmap {
        grid-area: 1 / 1;
        align-self: center;

        display: flex;
        height: 8px;
        border-radius: 4px;
        overflow: hidden;
        pointer-events: none;
        z-index: 0;
    }

    .heatmap span {
        flex: 1 1 0;
        background: #008fff;
    }

    input[type="range"] {
        grid-area: 1 / 1;
        align-self: center;

        appearance: none;
        -webkit-appearance: none;
        position: relative;
        z-index: 1;
        height: 8px;
        border-radius: 5px;
        background: #ffffff2e;
        cursor: pointer;

        &:hover::-webkit-slider-thumb {
            transform: scale(1.5);
        }
    }

    input[type="range"]::-webkit-slider-thumb {
        -webkit-appearance: none;
        height: 15px;
        width: 5px;
        border-radius: 3px;
        background: #eee;
        transition: all .25s ease-out;
    }

    input[type="range"]::-webkit-slider-runnable-track {
        -webkit-appearance: none;
        box-shadow: none;
        border: none;
        background: transparent;
    }
</style>
