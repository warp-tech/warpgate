<script module lang="ts">
    /** eslint-disable @typescript-eslint/ban-ts-comment */
</script>
<script lang="ts">
    import { run } from 'svelte/legacy'

    import { onDestroy, onMount } from 'svelte'
    import { createPopper } from '@popperjs/core'
    import { classnames, uuid } from './_sveltestrapUtils'
    import { Portal, InlineContainer } from '@sveltestrap/sveltestrap'

    interface Props {
        class?: string
        animation?: boolean
        container?: string
        id?: string
        isOpen?: boolean
        placement?: string
        target?: string | HTMLElement
        theme?: string | null
        delay?: string | number
        children: () => any
        [key: string]: any
    }

    let {
        'class': className = '',
        animation = true,
        container = undefined,
        id = `tooltip_${uuid()}`,
        isOpen = $bindable(false),
        placement = 'top',
        target = '',
        theme = null,
        delay = 0,
        children,
        ...rest
    }: Props = $props()

    /**
    * @type {string}
    */
    let bsPlacement: string = $state('')
    /**
    * @type {object}
    */
    let popperInstance: any = $state()
    /**
    * @type {string}
    */
    let popperPlacement = $state(placement)
    /**
    * @type {any}
    */
    let targetEl: any = $state()
    /**
    * @type {any}
    */
    let tooltipEl: any = $state()
    /**
    * @type {any}
    */
    let showTimer: any

    const checkPopperPlacement = {
        name: 'checkPopperPlacement',
        enabled: true,
        phase: 'main',
        fn({ state }: any) {
            popperPlacement = state.placement
        },
    }


    const open = () => {
        clearTimeout(showTimer)
        showTimer = setTimeout(() => (isOpen = true), delay as any)
    }

    const close = () => {
        clearTimeout(showTimer)
        isOpen = false
    }

    onMount(registerEventListeners)

    onDestroy(() => {
        unregisterEventListeners()
        clearTimeout(showTimer)
    })


    function registerEventListeners() {

        if (target == null || !target) {
            targetEl = null
            return
        }

        // Check if target is HTMLElement
        try {
            if (target instanceof HTMLElement) {
                targetEl = target
            }
        } catch {
            // fails on SSR
        }

        // If targetEl has not been found yet

        if (targetEl == null) {
            // Check if target can be found via querySelector
            try {
                targetEl = document.querySelector(`#${target}`)
            } catch {
                // fails on SSR
            }
        }

        // If we've found targetEl
        if (targetEl) {
            targetEl.addEventListener('mouseover', open)
            targetEl.addEventListener('mouseleave', close)
            targetEl.addEventListener('focus', open)
            targetEl.addEventListener('blur', close)
        }
    }

    function unregisterEventListeners() {
        if (targetEl) {
            targetEl.removeEventListener('mouseover', open)
            targetEl.removeEventListener('mouseleave', close)
            targetEl.removeEventListener('focus', open)
            targetEl.removeEventListener('blur', close)
            targetEl.removeAttribute('aria-describedby')
        }
    }

    run(() => {
        if (isOpen && tooltipEl) {
            popperInstance = createPopper(targetEl, tooltipEl, {
                placement,
                modifiers: [checkPopperPlacement],
            } as any)
        } else if (popperInstance) {
            popperInstance.destroy()
            popperInstance = undefined
        }
    })
    run(() => {
        if (target) {
            unregisterEventListeners()
            registerEventListeners()
        }
    })
    run(() => {
        if (targetEl) {
            if (isOpen) {
                targetEl.setAttribute('aria-describedby', id)
            } else {
                targetEl.removeAttribute('aria-describedby')
            }
        }
    })
    run(() => {
        if (popperPlacement === 'left') {
            bsPlacement = 'start'
        } else if (popperPlacement === 'right') {
            bsPlacement = 'end'
        } else {
            bsPlacement = popperPlacement
        }
    })
    let classes = $derived(classnames(
        className,
        'tooltip',
        `bs-tooltip-${bsPlacement}`,
        animation ? 'fade' : false,
        isOpen ? 'show' : false
    ))
    let outer = $derived(container === 'inline' ? InlineContainer : Portal)
</script>

{#if isOpen}
{@const SvelteComponent = outer}
<SvelteComponent>
    <div
    bind:this={tooltipEl}
    {...rest}
    class={classes}
    {id}
    role="tooltip"
    data-bs-theme={theme}
    data-bs-delay={delay}
    >
    <div class="tooltip-arrow" data-popper-arrow></div>
    <div class="tooltip-inner">
        {@render children?.()}
    </div>
</div>
</SvelteComponent>
{/if}
