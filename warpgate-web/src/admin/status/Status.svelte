<script lang="ts">
    import NavListItem from 'common/NavListItem.svelte'
    import Router, { type RouteDetail } from 'svelte-spa-router'
    import { wrap } from 'svelte-spa-router/wrap'

    const routes = {
        '/sessions': wrap({
            asyncComponent: () => import('./Sessions.svelte'),
        }),
        '/sessions/:id': wrap({
            asyncComponent: () => import('./Session.svelte'),
        }),
        '/requests': wrap({
            asyncComponent: () => import('./Requests.svelte'),
        }),
        '/login-protection': wrap({
            asyncComponent: () => import('./LoginProtection.svelte'),
        }),
        '/network': wrap({
            asyncComponent: () => import('./NetworkStatus.svelte'),
        }),
    }

    let sidebarMode = $state(false)

    function onRouteLoading(detail: RouteDetail) {
        sidebarMode = detail.route !== ''
    }
</script>

{#snippet navItems()}
    <NavListItem
        class="mb-2"
        title="Sessions"
        description="Active and past connections"
        href="/status/sessions"
        small={sidebarMode}
    />

    <NavListItem
        class="mb-2"
        title="Requests"
        description="Sessions and tickets awaiting your action"
        href="/status/requests"
        small={sidebarMode}
    />

    <NavListItem
        class="mb-2"
        title="Login protection"
        description="View blocked IPs and locked users"
        href="/status/login-protection"
        small={sidebarMode}
    />

    <NavListItem
        class="mb-2"
        title="Network status"
        description="Listeners, certificates and client IP detection"
        href="/status/network"
        small={sidebarMode}
    />
{/snippet}

<div class="wrapper" class:d-none={!sidebarMode}>
    <div class="sidebar">
        {@render navItems()}
    </div>

    <div class="main">
        <Router {routes} prefix="/status" {onRouteLoading} />
    </div>
</div>

<div class="container-max-md" class:d-none={sidebarMode}>
    {@render navItems()}
</div>

<style lang="scss">
    $sb-w: 200px;
    $sb-m: 30px;

    .wrapper {
        display: flex;
        gap: $sb-m;

        > .sidebar {
            width: $sb-w;
            flex: none;
        }

        > .main {
            flex: 1 0 0;
            max-width: 100%;
        }
    }

    @media (max-width: #{720px + $sb-m + $sb-w}) {
        .sidebar {
            display: none;
        }
    }
</style>
