<script lang="ts">
    // Copied from Sveltestrap and tweaked for S5 compatibility

    import { fade as fadeTransition } from 'svelte/transition'
    import { classnames } from './_sveltestrapUtils'

    /**
    * Additional CSS classes for container element.
    * @type {string}
    * @default ''
    */

    interface Props {
        class?: string;
        closeAriaLabel?: string;
        closeClassName?: string;
        color?: string;
        dismissible?: boolean;
        fade?: boolean;
        heading?: string;
        isOpen?: boolean;
        toggle?: CallableFunction;
        theme?: string | undefined;
        transition?: object;
        headingSlot?: import('svelte').Snippet;
        children: () => any
        [key: string]: any
    }

    let {
        'class': className = '',
        closeAriaLabel = 'Close',
        closeClassName = '',
        color = 'success',
        dismissible = false,
        fade = true,
        heading = '',
        isOpen = $bindable(true),
        toggle = undefined,
        theme = undefined,
        transition = { duration: fade ? 400 : 0 },
        headingSlot,
        children,
        ...rest
    }: Props = $props()

    let showClose = $derived(dismissible || toggle)
    let handleToggle = $derived(toggle ?? (() => (isOpen = false)))
    let classes = $derived(classnames(className, 'alert', `alert-${color}`, {
        'alert-dismissible': showClose,
    }))
    let closeClassNames = $derived(classnames('btn-close', closeClassName))
</script>

{#if isOpen}
<div {...rest} data-bs-theme={theme} transition:fadeTransition={transition} class={classes} role="alert">
    {#if heading || headingSlot}
    <h4 class="alert-heading">
        {heading}{@render headingSlot?.()}
    </h4>
    {/if}
    {#if showClose}
    <button type="button" class={closeClassNames} aria-label={closeAriaLabel} onclick={handleToggle as any}></button>
    {/if}
    {@render children?.()}
</div>
{/if}
