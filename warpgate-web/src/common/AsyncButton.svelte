<script lang="ts">
import { Button, Spinner } from 'sveltestrap'
import type { ButtonColor } from 'sveltestrap/src/Button'

export let click: CallableFunction
export let color: ButtonColor = 'secondary'
export let disabled = false
export let outline = false
export let type = 'submit'
let busy = false

async function _click () {
    busy = true
    try {
        await click()
    } finally {
        busy = false
    }
}

</script>

<Button
    on:click={_click}
    outline={outline}
    color={color}
    type={type}
    disabled={disabled || busy}
>
    <slot />
    {#if busy}
        <Spinner size="sm" />
    {/if}
</Button>
