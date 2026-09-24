<script lang="ts">
    /**
     * Render children only if the given admin permission is granted.
     * If not, `message` is shown instead (defaults to nothing).
     */
    import Callout from 'ui/Callout.svelte'
    import { type AdminPermissionKey, adminPermissions } from './store'

    export let perm: AdminPermissionKey
    export let message: string | undefined
</script>

{#if $adminPermissions[perm]}
    <slot />
{:else if message}
    <Callout tone="warning" title="Not available to your role">
        {message}
    </Callout>
{/if}
