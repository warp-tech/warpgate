<script lang="ts">
    import NavListItem from 'common/NavListItem.svelte'
    import { serverInfo } from 'gateway/lib/store'
    import Router, { type RouteDetail } from 'svelte-spa-router'
    import { wrap } from 'svelte-spa-router/wrap'

    const routes = {
        '/targets/create/:kind': wrap({
            asyncComponent: () => import('./targets/CreateTarget.svelte'),
        }),
        '/targets/create': wrap({
            asyncComponent: () => import('./targets/ChooseTargetKind.svelte'),
        }),
        '/targets/:id': wrap({
            asyncComponent: () => import('./targets/Target.svelte'),
        }),
        '/access-roles/create': wrap({
            asyncComponent: () => import('./CreateRole.svelte'),
        }),
        '/access-roles/:id': wrap({
            asyncComponent: () => import('./AccessRole.svelte'),
        }),
        '/admin-roles/create': wrap({
            asyncComponent: () => import('./CreateAdminRole.svelte'),
        }),
        '/admin-roles/:id': wrap({
            asyncComponent: () => import('./AdminRole.svelte'),
        }),
        '/users/create': wrap({
            asyncComponent: () => import('./CreateUser.svelte'),
        }),
        '/users/:id': wrap({
            asyncComponent: () => import('./users/User.svelte'),
        }),
        '/users': wrap({
            asyncComponent: () => import('./users/Users.svelte'),
        }),
        '/parameters': wrap({
            asyncComponent: () => import('./Parameters.svelte'),
        }),
        '/access-roles': wrap({
            asyncComponent: () => import('./AccessRoles.svelte'),
        }),
        '/admin-roles': wrap({
            asyncComponent: () => import('./AdminRoles.svelte'),
        }),
        '/targets': wrap({
            asyncComponent: () => import('./targets/Targets.svelte'),
        }),
        '/ssh': wrap({
            asyncComponent: () => import('./SSHKeys.svelte'),
        }),
        '/tickets': wrap({
            asyncComponent: () => import('./Tickets.svelte'),
        }),
        '/tickets/create': wrap({
            asyncComponent: () => import('./CreateTicket.svelte'),
        }),
        '/ldap-servers': wrap({
            asyncComponent: () => import('./ldap/LdapServers.svelte'),
        }),
        '/ldap-servers/create': wrap({
            asyncComponent: () => import('./ldap/CreateLdapServer.svelte'),
        }),
        '/ldap-servers/:id': wrap({
            asyncComponent: () => import('./ldap/LdapServer.svelte'),
        }),
        '/ldap-servers/:id/users': wrap({
            asyncComponent: () => import('./ldap/LdapUserBrowser.svelte'),
        }),
        '/target-groups/create': wrap({
            asyncComponent: () =>
                import('./target-groups/CreateTargetGroup.svelte'),
        }),
        '/target-groups/:id': wrap({
            asyncComponent: () => import('./target-groups/TargetGroup.svelte'),
        }),
        '/target-groups': wrap({
            asyncComponent: () => import('./target-groups/TargetGroups.svelte'),
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
        title="Targets"
        description="Destinations for users to connect to"
        href="/config/targets"
        small={sidebarMode}
    />

    <NavListItem
        class="mb-2"
        title="Target groups"
        description="Organize targets into groups"
        href="/config/target-groups"
        small={sidebarMode}
    />

    <NavListItem
        class="mb-2"
        title="Users"
        description="Manage accounts and credentials"
        href="/config/users"
        small={sidebarMode}
    />

    <NavListItem
        class="mb-2"
        title="Access roles"
        description="Grant users access to roles"
        href="/config/access-roles"
        small={sidebarMode}
    />

    <NavListItem
        class="mb-2"
        title="Admin roles"
        description="Grant users access to the admin UI"
        href="/config/admin-roles"
        small={sidebarMode}
    />

    <NavListItem
        class="mb-2"
        title="Tickets"
        description={$serverInfo?.ticketSelfServiceEnabled
            ? 'Access credentials — users can request tickets from their profile'
            : 'Temporary access credentials'}
        href="/config/tickets"
        small={sidebarMode}
    />

    <NavListItem
        class="mb-2"
        title="SSH keys"
        description="Own keys and known hosts"
        href="/config/ssh"
        small={sidebarMode}
    />

    <NavListItem
        class="mb-2"
        title="LDAP servers"
        description="Connect to directory services"
        href="/config/ldap-servers"
        small={sidebarMode}
    />

    <NavListItem
        class="mb-2"
        title="Global parameters"
        description="Change instance-wide settings"
        href="/config/parameters"
        small={sidebarMode}
    />

    <NavListItem
        class="mb-2"
        title="Login protection"
        description="View blocked IPs and locked users"
        href="/config/login-protection"
        small={sidebarMode}
    />

    <NavListItem
        class="mb-2"
        title="Network status"
        description="Listeners, certificates and client IP detection"
        href="/config/network"
        small={sidebarMode}
    />
{/snippet}

<div class="wrapper" class:d-none={!sidebarMode}>
    <div class="sidebar">
        {@render navItems()}
    </div>

    <div class="main">
        <Router {routes} prefix="/config" {onRouteLoading} />
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
