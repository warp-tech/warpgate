<script lang="ts">
    import NavListItem from 'common/NavListItem.svelte'
    import { wrap } from 'svelte-spa-router/wrap'
    import Router from 'svelte-spa-router'

    const routes = {
        '/targets/create': wrap({
            asyncComponent: () => import('./CreateTarget.svelte') as any,
        }),
        '/targets/:id': wrap({
            asyncComponent: () => import('./targets/Target.svelte') as any,
        }),
        '/roles/create': wrap({
            asyncComponent: () => import('./CreateRole.svelte') as any,
        }),
        '/roles/:id': wrap({
            asyncComponent: () => import('./Role.svelte') as any,
        }),
        '/users/create': wrap({
            asyncComponent: () => import('./CreateUser.svelte') as any,
        }),
        '/users/:id': wrap({
            asyncComponent: () => import('./User.svelte') as any,
        }),
        '/parameters': wrap({
            asyncComponent: () => import('./Parameters.svelte') as any,
        }),
        '/users': wrap({
            asyncComponent: () => import('./Users.svelte') as any,
        }),
        '/roles': wrap({
            asyncComponent: () => import('./Roles.svelte') as any,
        }),
        '/targets': wrap({
            asyncComponent: () => import('./targets/Targets.svelte') as any,
        }),
        '/ssh': wrap({
            asyncComponent: () => import('./SSHKeys.svelte') as any,
        }),
        '/tickets': wrap({
            asyncComponent: () => import('./Tickets.svelte') as any,
        }),
        '/tickets/create': wrap({
            asyncComponent: () => import('./CreateTicket.svelte') as any,
        }),
        '/ldap-servers': wrap({
            asyncComponent: () => import('./ldap/LdapServers.svelte') as any,
        }),
        '/ldap-servers/create': wrap({
            asyncComponent: () => import('./ldap/CreateLdapServer.svelte') as any,
        }),
        '/ldap-servers/:id': wrap({
            asyncComponent: () => import('./ldap/LdapServer.svelte') as any,
        }),
        '/ldap-servers/:id/users': wrap({
            asyncComponent: () => import('./ldap/LdapUserBrowser.svelte') as any,
        }),
        '/target-groups/create': wrap({
            asyncComponent: () => import('./target-groups/CreateTargetGroup.svelte') as any,
        }),
        '/target-groups/:id': wrap({
            asyncComponent: () => import('./target-groups/TargetGroup.svelte') as any,
        }),
        '/target-groups': wrap({
            asyncComponent: () => import('./target-groups/TargetGroups.svelte') as any,
        }),
    }

    let sidebarMode = $state(false)
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
        title="Target Groups"
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
        title="Roles"
        description="Group users together"
        href="/config/roles"
        small={sidebarMode}
    />

    <NavListItem
        class="mb-2"
        title="Tickets"
        description="Temporary access credentials"
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
        title="LDAP Servers"
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
{/snippet}

<div class="wrapper" class:d-none={!sidebarMode}>
    <div class="sidebar">
        <!-- eslint-disable-next-line @typescript-eslint/no-confusing-void-expression -->
        {@render navItems()}
    </div>

    <div class="main">
        <Router {routes} prefix="/config" on:routeLoading={e => {
            sidebarMode = e.detail.route !== ''
        }} />
    </div>
</div>

<div class="container-max-md" class:d-none={sidebarMode}>
    <!-- eslint-disable-next-line @typescript-eslint/no-confusing-void-expression -->
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
        }
    }

    @media (max-width: #{720px + $sb-m + $sb-w}) {
        .sidebar {
            display: none;
        }
    }
</style>
