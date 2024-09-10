<script lang="ts">
import { faCheck } from '@fortawesome/free-solid-svg-icons'
import Fa from 'svelte-fa'
import { Button, Spinner, type Color } from '@sveltestrap/sveltestrap'

enum State {
    Normal = 'n',
    Progress = 'p',
    ProgressWithSpinner = 'ps',
    Done = 'd'
}

export let click: CallableFunction
export let color: Color | 'link' = 'secondary'
export let disabled = false
export let outline = false
export let type = 'submit'
let button: HTMLElement
let lastWidth = 0
let state = State.Normal

async function _click () {
    lastWidth = button.offsetWidth
    state = State.Progress
    setTimeout(() => {
        if (state === State.Progress) {
            state = State.ProgressWithSpinner
        }
    }, 500)
    try {
        await click()
    } finally {
        state = State.Done
        setTimeout(() => {
            if (state === State.Done) {
                state = State.Normal
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
    class={$$props.class}
    outline={outline}
    color={color}
    type={type}
    disabled={disabled || state === State.Progress || state === State.ProgressWithSpinner}
>
    {#if state === State.Normal || state === State.Progress}
        <slot />
    {/if}
    <div class="overlay">
        {#if state === State.ProgressWithSpinner}
            <Spinner size="sm" />
        {/if}
        {#if state === State.Done}
            <Fa icon={faCheck} fw />
        {/if}
    </div>
</Button>
