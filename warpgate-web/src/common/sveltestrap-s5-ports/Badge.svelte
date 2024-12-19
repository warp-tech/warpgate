<script>
    import { classnames } from './_sveltestrapUtils'


    /**
    * Additional CSS classes for container element.
    * @type {string}
    * @default ''
    */


    /**
     * @typedef {Object} Props
     * @property {string} [ariaLabel] - Text to be read by screen readers.
     * @property {boolean | string} [border] - Determines if the badge should have a border
     * @property {string} [class]
     * @property {string} [children] - The content to be displayed within the badge.
     * @property {string} [color] - The color theme for the badge.
     * @property {string} [href] - The href attribute for the badge, which turns it into a link if provided.
     * @property {boolean} [indicator] - Create a circular indicator for absolute positioned badge.
     * @property {boolean} [pill] - Flag to indicate if the badge should have a pill shape.
     * @property {boolean} [positioned] - Flag to indicate if the badge should be absolutely positioned.
     * @property {string} [placement] - Classes determining where the badge should be absolutely positioned.
     * @property {boolean | string} [shadow] - Determines if the badge should have a shadow
     * @property {string | undefined} [theme] - The theme name override to apply to this component instance.
     * @property {CallableFunction} [children]
     */

    let {
        ariaLabel = '',
        border = false,
        'class': className = '',
        color = 'secondary',
        href = '',
        indicator = false,
        pill = false,
        positioned = false,
        placement = 'top-0 start-100',
        shadow = false,
        theme = undefined,
        children,
        ...rest
    } = $props()

    let classes = $derived(classnames(
        'badge',
        `text-bg-${color}`,
        pill ? 'rounded-pill' : false,
        positioned ? 'position-absolute translate-middle' : false,
        positioned ? placement : false,
        indicator ? 'p-2' : false,
        border ? (typeof border === 'string' ? border : 'border') : false,
        shadow ? (typeof shadow === 'string' ? shadow : 'shadow') : false,
        className
    ))
</script>

{#if href}
<a {...rest} {href} class={classes} data-bs-theme={theme}>
    {@render children?.()}
    {#if positioned || indicator}
    <span class="visually-hidden">{ariaLabel}</span>
    {/if}
</a>
{:else}
<span {...rest} class={classes} data-bs-theme={theme}>
    {@render children?.()}
    {#if positioned || indicator}
    <span class="visually-hidden">{ariaLabel}</span>
    {/if}
</span>
{/if}
