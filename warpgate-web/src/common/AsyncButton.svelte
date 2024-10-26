<script lang="ts">
import { faCheck } from '@fortawesome/free-solid-svg-icons'
import Fa from 'svelte-fa'
import { Button, Spinner, type Color } from '@sveltestrap/sveltestrap'

// svelte-ignore non_reactive_update
enum State {
    Normal = 'n',
    Progress = 'p',
    ProgressWithSpinner = 'ps',
    Done = 'd'
}

interface Props {
    click: CallableFunction
    color?: Color | 'link'
    disabled?: boolean
    outline?: boolean
    type?: 'button' | 'submit' | 'reset'
    class?: string
    children: () => any
}

let { children, click, color  = 'secondary', disabled = false, outline = false, type = 'submit', 'class': cls = '' }: Props = $props()

let button: HTMLElement | undefined = $state()
let lastWidth = $state(0)
let st = $state(State.Normal)

async function _click () {
    if (!button) {
        return
    }
    lastWidth = button.offsetWidth
    st = State.Progress
    setTimeout(() => {
        if (st === State.Progress) {
            st = State.ProgressWithSpinner
        }
    }, 500)
    try {
        await click()
    } finally {
        st = State.Done
        setTimeout(() => {
            if (st === State.Done) {
                st = State.Normal
                lastWidth = 0
            }
        }, 1000)
    }
}

</script>

<Button
    on:click={_click}
    bind:inner={button}
    style="min-width: {lastWidth}px"
    class={cls}
    outline={outline}
    color={color}
    type={type}
    disabled={disabled || st === State.Progress || st === State.ProgressWithSpinner}
>
    {#if st === State.Normal || st === State.Progress}
        {@render children?.()}
    {/if}
    <div class="overlay">
        {#if st === State.ProgressWithSpinner}
            <Spinner size="sm" />
        {/if}
        {#if st === State.Done}
            <Fa icon={faCheck} fw />
        {/if}
    </div>
</Button>
