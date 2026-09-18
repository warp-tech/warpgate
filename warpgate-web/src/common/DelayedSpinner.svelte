<script lang="ts">
    /**
     * Kept as a name, not as an implementation. ui/Spinner grew a `delay`
     * prop that does exactly what this component did, so this is now a
     * one-line alias so the ~8 existing call sites keep working without a
     * mechanical rename.
     */
    import Spinner from 'ui/Spinner.svelte'
</script>

<div class="delayed-spinner">
    <Spinner delay={1000} size={20} label="Loading" />
</div>

<style>
    .delayed-spinner {
        display: flex;
        justify-content: center;
        margin: var(--wg-space-3xl) auto;
    }
</style>
