<script lang="ts">
import { Button, Spinner } from 'sveltestrap'
import type { ButtonColor } from 'sveltestrap/src/Button'

export let click: CallableFunction
export let color: ButtonColor = 'secondary'
export let disabled = false
export let outline = false
export let type = 'submit'
let busy = false
let spinnerVisible = false

async function _click () {
    busy = true
    setTimeout(() => {
        if (busy) {
            spinnerVisible = true
        }
    }, 500)
    try {
        await click()
    } finally {
        busy = false
        spinnerVisible = false
    }
}

</script>

<Button
    on:click={_click}
    class={$$props.class}
    outline={outline}
    color={color}
    type={type}
    disabled={disabled || busy}
>
    <slot />
    {#if spinnerVisible}
        <Spinner size="sm" />
    {/if}
</Button>
