<script lang="ts">
    import Fa from 'svelte-fa'
    import { faPlay, faPause, faExpand } from '@fortawesome/free-solid-svg-icons'
    import formatDuration from 'format-duration'

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
    <button class="btn btn-link" on:click={onTogglePlaying}>
        <Fa icon={playing ? faPause : faPlay} fw />
    </button>
    <pre class="timestamp">{ formatDuration(timestamp * 1000, { leading: true }) }</pre>
    {#if isLive}
        <button
            class="btn live-btn"
            class:active={liveActive}
            on:click={onGoLive}
        >LIVE</button>
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
            min="0" max="100" step="0.001"
            style="background-size: {seekInputValue}% 100%;"
            bind:value={seekInputValue}
            on:input={() => onSeek(seekInputValue)} />
    </div>
    <button class="btn btn-link" on:click={onToggleFullscreen}>
        <Fa icon={faExpand} fw />
    </button>
</div>

<style lang="scss">
    .toolbar {
        display: flex;
    }

    .btn {
        color: #eee;

        :global(svg) {
            transition: all .25s ease-out;
            &:hover {
                transform: scale(1.2);
            }
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

    .live-btn {
        font-size: 0.75rem;
        align-self: center;
        color: red;
        flex: none;

        &.active {
            background: red;
            color: white;
            padding: 0.1rem 0.25rem;
            margin: 0 0.5rem;
        }
    }

    .seek {
        position: relative;
        flex: 1 1 auto;
        display: flex;
        align-items: center;
    }

    // Input-event density band behind the scrubber. Taller than the 2px track so it
    // reads as a coloured halo around the thin white scrubber line + fill on top.
    .heatmap {
        position: absolute;
        left: 10px;
        right: 10px;
        top: 19px;
        height: 8px;
        transform: translateY(-50%);
        display: flex;
        border-radius: 4px;
        overflow: hidden;
        pointer-events: none;
        z-index: 0;
        background: rgba(255, 255, 255, 0.06);
    }

    .heatmap span {
        flex: 1 1 0;
        background: #5bc0be;
    }

    input[type="range"] {
        appearance: none;
        -webkit-appearance: none;
        position: relative;
        z-index: 1;
        margin: 18px 10px 0;
        height: 2px;
        border-radius: 5px;
        background: linear-gradient(#eee, #eee);
        background-repeat: no-repeat;
        cursor: pointer;

        &:hover::-webkit-slider-thumb {
            transform: scale(1.5);
        }
    }

    input[type="range"]::-webkit-slider-thumb {
        -webkit-appearance: none;
        height: 10px;
        width: 10px;
        border-radius: 50%;
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
