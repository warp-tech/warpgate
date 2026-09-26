<script lang="ts" generics="T">
    import { Alert } from '@sveltestrap/sveltestrap'
    import type { Snippet } from 'svelte'
    import DelayedSpinner from './DelayedSpinner.svelte'
    import { stringifyError } from './errors'

    let {
        promise,
        value = $bindable(),
        children,
    }: {
        promise: Promise<T>
        /**
         * Bind this to the variable holding the loaded value to keep the
         * children snippet in sync when the page later reassigns it —
         * otherwise the snippet only sees the value the promise resolved to.
         */
        value?: T
        children?: Snippet<[T]>
    } = $props()

    let loaded = $state(false)
    let resolved = $state(false)
    let error: string | undefined = $state()

    // "resolved" guards against rendering before the value is set, since on
    // rejection `loaded` becomes true before the async stringifyError lands.
    const currentValue = $derived(value as T)

    $effect(() => {
        loaded = false
        resolved = false
        promise
            .then(d => {
                value = d
                resolved = true
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
{:else if error}
    <Alert color="danger">
        {error}
    </Alert>
{:else if resolved}
    {@render children?.(currentValue)}
{/if}
