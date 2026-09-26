<script lang="ts">
    import { Badge, Tooltip } from '@sveltestrap/sveltestrap'
    import { uuid } from './helpers'

    interface DatedCredential {
        lastUsed?: Date
        dateAdded?: Date
    }

    export let credential: DatedCredential

    const id = uuid()
    const lastUseThreshold = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000)
    let badge: HTMLElement | undefined
</script>

<span bind:this={badge}>
    {#if credential.lastUsed}
        {#if credential.lastUsed.getTime() < lastUseThreshold.getTime()}
            <Badge {id} color="warning">Not used recently</Badge>
        {:else}
            <Badge {id} color="success">Used recently</Badge>
        {/if}
    {:else}
        <Badge {id} color="warning">Never used</Badge>
    {/if}
</span>

{#if credential.dateAdded || credential.lastUsed}
    <Tooltip target={badge} animation delay="250">
        {#if credential.dateAdded}
            <div>
                Added on: {new Date(credential.dateAdded).toLocaleString()}
            </div>
        {/if}
        {#if credential.lastUsed}
            <div>
                Last used: {new Date(credential.lastUsed).toLocaleString()}
            </div>
        {/if}
    </Tooltip>
{/if}
