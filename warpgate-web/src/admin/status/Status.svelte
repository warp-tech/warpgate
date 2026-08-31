<script lang="ts">
    import SidebarNavContainer from 'admin/config/SidebarNavContainer.svelte'
    import NavListItem from 'common/NavListItem.svelte'
    import { wrap } from 'svelte-spa-router/wrap'

    const routes = {
        '/sessions': wrap({
            asyncComponent: () => import('./Sessions.svelte'),
        }),
        '/sessions/:id': wrap({
            asyncComponent: () => import('./Session.svelte'),
        }),
        '/commands': wrap({
            asyncComponent: () => import('./Commands.svelte'),
        }),
        '/login-protection': wrap({
            asyncComponent: () => import('./LoginProtection.svelte'),
        }),
        '/network': wrap({
            asyncComponent: () => import('./NetworkStatus.svelte'),
        }),
    }
</script>

<SidebarNavContainer {routes} prefix="/status" returnLink>
    {#snippet navItems()}
        <NavListItem
            small
            class="mb-2"
            title="Sessions"
            description="Active and past connections"
            href="/status/sessions"
        />

        <NavListItem
            small
            class="mb-2"
            title="Commands"
            description="Search shell commands recorded in SSH sessions"
            href="/status/commands"
        />

        <NavListItem
            small
            class="mb-2"
            title="Login protection"
            description="View blocked IPs and locked users"
            href="/status/login-protection"
        />

        <NavListItem
            small
            class="mb-2"
            title="Network status"
            description="Listeners, certificates and client IP detection"
            href="/status/network"
        />
    {/snippet}
</SidebarNavContainer>
