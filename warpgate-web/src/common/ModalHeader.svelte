<script>
    import { classnames } from './_sveltestrapUtils'

    /**
    * @typedef {Object} Props
    * @property {string} [class]
    * @property {boolean | CallableFunction | undefined} [toggle] - Determines whether the modal header includes a close button.
    * @property {string} [closeAriaLabel] - The aria-label for the close button.
    * @property {string} [id] - The unique id of the modal header.
    * @property {any} [children]
    * @property {import('svelte').Snippet} [children]
    * @property {import('svelte').Snippet} [close]
    */

    /** @type {Props & { [key: string]: any }} */
    let {
        'class': className = '',
        toggle = undefined,
        closeAriaLabel = 'Close',
        children,
        close,
    } = $props()

    let classes = $derived(classnames(className, 'modal-header'))
</script>

<div class={classes}>
    <h5 class="modal-title">
        {@render children()}
    </h5>
    {#if close}{@render close()}{:else}
    {#if typeof toggle === 'function'}
    <button type="button" onclick={() => toggle()} class="btn-close" aria-label={closeAriaLabel}></button>
    {/if}
    {/if}
</div>
