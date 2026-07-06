<script lang="ts">
    import { Alert } from '@sveltestrap/sveltestrap'
    import { type AdminPermissionKey, adminPermissions } from './store'

    /**
     * Render children only if the given admin permission is granted.
     * If not, the content placed in the `fallback` slot will be shown
     * instead (defaults to nothing).
     */
    export let perm: AdminPermissionKey

    export let message: string | undefined
</script>

{#if $adminPermissions[perm]}
    <slot />
{:else}
    {#if message}
        <Alert color="warning">
            {message}
        </Alert>
    {/if}
{/if}
