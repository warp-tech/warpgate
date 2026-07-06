<script lang="ts" generics="T">
    import { Alert } from '@sveltestrap/sveltestrap'
    import type { Snippet } from 'svelte'
    import DelayedSpinner from './DelayedSpinner.svelte'
    import { stringifyError } from './errors'

    let {
        promise,
        children,
    }: {
        promise: Promise<T>
        children: Snippet<[T]>
    } = $props()

    let loaded = $state(false)
    const EMPTY = Symbol()
    let data = $state<T | typeof EMPTY>(EMPTY)
    let error: string | undefined = $state()

    $effect(() => {
        loaded = false
        data = EMPTY
        promise
            .then(d => {
                data = d
            })
            .catch(err => {
                stringifyError(err).then(e => {
                    error = e
                })
            })
            .finally(() => {
                loaded = true
            })
    })
</script>

{#if !loaded}
    <DelayedSpinner />
{:else}
    {#if !error}
        {#if data !== EMPTY}
            {@render children?.(data)}
        {/if}
    {:else}
        <Alert color="danger">
            {error}
        </Alert>
    {/if}
{/if}
