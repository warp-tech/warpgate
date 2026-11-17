<script lang="ts">
    import { type SidebarItem, useSidebar } from 'common/sidebarState.svelte'
    import { serverInfo } from 'gateway/lib/store'
    import Router from 'svelte-spa-router'
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
        '/gitops': wrap({
            asyncComponent: () => import('./GitopsHistory.svelte'),
        }),
    }

    const sidebarItems = $derived.by<SidebarItem[]>(() =>
        [
            {
                title: 'Sessions',
                href: '/status/sessions',
            },
            {
                title: 'Requests',
                href: '/status/requests',
            },
            $serverInfo?.gitopsSync
                ? {
                      title: 'GitOps',
                      href: '/status/gitops',
                  }
                : null,
            {
                title: 'Login protection',
                href: '/status/login-protection',
            },
            {
                title: 'Network status',
                href: '/status/network',
            },
        ].filter(x => !!x),
    )
    useSidebar(() => sidebarItems)
</script>

<Router {routes} prefix="/status" />
