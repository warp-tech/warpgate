<script lang="ts">
import { faCheck, faCopy } from '@fortawesome/free-solid-svg-icons'
import Fa from 'svelte-fa'
import { Button, Color } from '@sveltestrap/sveltestrap'
import copyTextToClipboard from 'copy-text-to-clipboard'

export let text: string
export let disabled = false
export let outline = false
export let link = false
export let color: Color | 'link' = 'link'
let successVisible = false
let button: HTMLElement

async function _click () {
    successVisible = true
    copyTextToClipboard(text)
    setTimeout(() => {
        successVisible = false
    }, 2000)
}

</script>

{#if link}
    <!-- svelte-ignore a11y-invalid-attribute -->
    <a
        href="#"
        class={$$props.class}
        on:click|preventDefault={_click}
        bind:this={button}
    >
        <slot>
            {#if successVisible}
                Copied
            {:else}
                Copy
            {/if}
        </slot>
    </a>
{:else}
    <Button
        class={$$props.class}
        bind:inner={button}
        on:click={_click}
        outline={outline}
        color={color}
        disabled={disabled}
    >
        <slot>
            {#if successVisible}
                <Fa fw icon={faCheck} />
            {:else}
                <Fa fw icon={faCopy} />
            {/if}
        </slot>
    </Button>
{/if}
