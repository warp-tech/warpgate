<script lang="ts">
    import { useSidebar } from 'common/sidebarState.svelte'
    import { serverInfo } from 'gateway/lib/store'
    import Router from 'svelte-spa-router'
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
        '/policies': wrap({
            asyncComponent: () => import('./Policies.svelte'),
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
        '/secret-backends': wrap({
            asyncComponent: () =>
                import('./secret-backends/SecretBackends.svelte'),
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
    }

    useSidebar(() => [
        {
            title: 'Targets',
            href: '/config/targets',
        },
        {
            title: 'Target groups',
            href: '/config/target-groups',
        },
        {
            title: 'Users',
            href: '/config/users',
        },
        {
            title: 'Access roles',
            href: '/config/access-roles',
        },
        {
            title: 'Admin roles',
            href: '/config/admin-roles',
        },
        {
            title: 'Tickets',
            href: '/config/tickets',
        },
        {
            title: 'SSH keys',
            href: '/config/ssh',
        },
        {
            title: 'Policies',
            href: '/config/policies',
        },
        {
            title: 'Global parameters',
            href: '/config/parameters',
        },
        {
            title: 'LDAP servers',
            href: '/config/ldap-servers',
        },
        {
            title: 'Secret backends',
            href: '/config/secret-backends',
        },
    ])
</script>

<Router {routes} prefix="/config" />
