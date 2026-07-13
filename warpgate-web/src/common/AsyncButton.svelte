<script lang="ts">
    import { faCheck, faTimes } from '@fortawesome/free-solid-svg-icons'
    import { Button, type Color, Spinner } from '@sveltestrap/sveltestrap'
    import type { Snippet } from 'svelte'
    import Fa from 'svelte-fa'

    // svelte-ignore non_reactive_update
    enum State {
        Normal = 'n',
        Progress = 'p',
        ProgressWithSpinner = 'ps',
        Done = 'd',
        Failed = 'f',
    }

    interface Props {
        click: CallableFunction
        color?: Color | 'link'
        disabled?: boolean
        outline?: boolean
        type?: 'button' | 'submit' | 'reset'
        class?: string
        size?: 'sm' | 'lg'
        id?: string
        children?: Snippet
    }

    let {
        children,
        click,
        color = 'secondary',
        disabled = false,
        outline = false,
        type = 'submit',
        class: cls = '',
        id = '',
        size,
    }: Props = $props()

    let button: HTMLElement | undefined = $state()
    let lastWidth = $state(0)
    let lastHeight = $state(0)
    let st = $state(State.Normal)

    async function _click() {
        if (!button) {
            return
        }

        const parentForm = button.closest<HTMLFormElement>('form')
        if (parentForm) {
            parentForm.classList.add('was-validated')
            if (!parentForm.checkValidity()) {
                return
            }
        }

        lastWidth = button.offsetWidth
        lastHeight = button.offsetHeight
        st = State.Progress
        setTimeout(() => {
            if (st === State.Progress) {
                st = State.ProgressWithSpinner
            }
        }, 500)
        try {
            await click()
            st = State.Done
        } catch (e) {
            st = State.Failed
            throw e
        } finally {
            setTimeout(() => {
                if (st === State.Done || st === State.Failed) {
                    st = State.Normal
                    lastWidth = 0
                    lastHeight = 0
                }
            }, 1000)
        }
    }
</script>

<Button
    on:click={_click}
    bind:inner={button}
    style="min-width: {lastWidth}px; min-height: {lastHeight}px;"
    class={cls}
    {outline}
    {color}
    {type}
    {size}
    {id}
    disabled={disabled || st === State.Progress || st === State.ProgressWithSpinner}
>
    {#if st === State.Normal || st === State.Progress}
        {#if children}
            {@render children()}
        {/if}
    {/if}
    <div class="overlay">
        {#if st === State.ProgressWithSpinner}
            <Spinner size="sm" />
        {/if}
        {#if st === State.Done}
            <Fa icon={faCheck} fw />
        {/if}
        {#if st === State.Failed}
            <Fa icon={faTimes} fw />
        {/if}
    </div>
</Button>

<style lang="scss">
    .overlay {
        margin: auto;

        :global(svg) {
            margin: auto;
        }
    }
</style>
