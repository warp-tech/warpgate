<script lang="ts">
    import { faCheck, faCopy } from '@fortawesome/free-solid-svg-icons'
    import Fa from 'svelte-fa'
    import { Button, type Color } from '@sveltestrap/sveltestrap'
    import copyTextToClipboard from 'copy-text-to-clipboard'

    interface Props {
        text: string
        disabled?: boolean
        outline?: boolean
        link?: boolean
        color?: Color | 'link'
        class?: string
        label?: string
        children?: () => any
    }

    // eslint-disable-next-line svelte/no-unused-props
    let {
        text,
        disabled = false,
        outline = false,
        link = false,
        color = 'link',
        label,
        'class': className = '',
        children,
    }: Props = $props()
    let successVisible = $state(false)
    let button: HTMLElement | undefined = $state()

    async function _click () {
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

{#if link}
    <!-- svelte-ignore a11y_invalid_attribute -->
    <a
        href="#"
        class={className}
        class:disabled={disabled}
        onclick={e => {
            _click()
            e.preventDefault()
        }}
        bind:this={button}
    >
        {#if children}{@render children()}{:else}
            {#if successVisible}
                Copied
            {:else}
                Copy
            {/if}
        {/if}
    </a>
{:else}
    <Button
        class={className}
        bind:inner={button}
        on:click={_click}
        outline={outline}
        color={color}
        disabled={disabled}
    >
        {#if children}{@render children()}{:else}
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
{/if}
