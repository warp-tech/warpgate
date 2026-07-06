<script lang="ts">
    import { faCheck, faCopy } from '@fortawesome/free-solid-svg-icons'
    import { Button, type Color } from '@sveltestrap/sveltestrap'
    import copyTextToClipboard from 'copy-text-to-clipboard'
    import type { Snippet } from 'svelte'
    import Fa from 'svelte-fa'

    interface Props {
        text: string
        disabled?: boolean
        outline?: boolean
        color?: Color | 'link'
        class?: string
        label?: string
        children?: Snippet
    }

    let {
        text,
        disabled = false,
        outline = false,
        color = 'link',
        label,
        class: className = '',
        children,
    }: Props = $props()
    let successVisible = $state(false)

    async function _click() {
        if (disabled) {
            return
        }
        successVisible = true
        copyTextToClipboard(text)
        setTimeout(() => {
            successVisible = false
        }, 2000)
    }
</script>

<Button class={className} on:click={_click} {outline} {color} {disabled}>
    {#if children}
        {@render children()}
    {:else}
        {#if successVisible}
            <Fa fw icon={faCheck} />
        {:else}
            <Fa fw icon={faCopy} />
        {/if}
        {#if label}
            <span class="ms-2">{label}</span>
        {/if}
    {/if}
</Button>
