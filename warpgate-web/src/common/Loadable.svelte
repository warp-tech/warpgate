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
    let resolvedOnce = $state(false)
    let resolved = $state(false)
    let error: string | undefined = $state()

    // "resolved" guards against rendering before the value is set, since on
    // rejection `loaded` becomes true before the async stringifyError lands.
    const currentValue = $derived(value as T)

    // Bumped per effect run so a slow earlier promise can't overwrite the
    // result of a later one, or resurrect an error the retry has cleared.
    let generation = 0

    $effect(() => {
        if (!resolvedOnce) {
            // only hide content when loading for the first time
            loaded = false
            resolved = false
        }
        // A retry starts clean: leaving the previous error set would replace the
        // content with a permanent alert after a single failed refresh.
        error = undefined

        generation += 1
        const current = generation
        promise
            .then(d => {
                if (current !== generation) {
                    return
                }
                value = d
                resolved = true
                resolvedOnce = true
            })
            .catch(err => {
                stringifyError(err).then(e => {
                    if (current === generation) {
                        error = e
                    }
                })
            })
            .finally(() => {
                if (current === generation) {
                    loaded = true
                }
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
