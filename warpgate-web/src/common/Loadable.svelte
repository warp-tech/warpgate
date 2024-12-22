<script lang="ts" generics="T">
    import type { Snippet } from 'svelte'
    import Alert from './sveltestrap-s5-ports/Alert.svelte'
    import DelayedSpinner from './DelayedSpinner.svelte'
    import { stringifyError } from './errors'

    let { promise, children }: {
        promise: Promise<T>
        children: Snippet<[T]>
    } = $props()

    let loaded = $state(false)
    let data: T | undefined = $state()
    let error: string | undefined = $state()

    $effect(() => {
        loaded = false
        data = undefined
        promise.then(d => {
            data = d
        }).catch(err => {
            stringifyError(err).then(e => {
                error = e
            })
        }).finally(() => {
            loaded = true
        })
    })

</script>

{#if !loaded}
    <DelayedSpinner />
{:else}
    {#if !error}
        {@render children?.(data!)}
    {:else}
        <Alert color="danger">
            {error}
        </Alert>
    {/if}
{/if}
