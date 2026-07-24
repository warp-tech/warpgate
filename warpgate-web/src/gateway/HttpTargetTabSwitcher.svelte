<script lang="ts">
    import {
        faUpRightFromSquare,
        faWindowMaximize,
    } from '@fortawesome/free-solid-svg-icons'
    import { Button, Tooltip } from '@sveltestrap/sveltestrap'
    import { openHttpInNewTab } from 'gateway/lib/store'
    import Fa from 'svelte-fa'

    function toggle() {
        openHttpInNewTab.update(v => !v)
    }
</script>

<Button
    color="link"
    on:click={toggle}
    id="http-tab-button"
    title="Toggle how HTTP targets open"
>
    {#if $openHttpInNewTab}
        <Fa fw icon={faUpRightFromSquare} />
    {:else}
        <Fa fw icon={faWindowMaximize} />
    {/if}
</Button>
<Tooltip target="http-tab-button" animation placement="left" container="body">
    {#if $openHttpInNewTab}
        HTTP targets open in a new tab
    {:else}
        HTTP targets open in the same tab
    {/if}
</Tooltip>
