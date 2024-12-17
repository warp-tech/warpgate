<script lang="ts">
    import NavListItem from 'common/NavListItem.svelte'
</script>

<NavListItem
    title="Targets"
    description="Destinations for users to connect to"
    href="/config/targets"
/>

<NavListItem
    title="Users"
    description="Manage accounts and credentials"
    href="/config/users"
/>

<NavListItem
    title="Roles"
    description="Group users together"
    href="/config/roles"
/>

<NavListItem
    title="Tickets"
    description="Temporary access credentials"
    href="/config/tickets"
/>

<NavListItem
    title="SSH keys"
    description="Own keys and known hosts"
    href="/config/ssh"
/>

<NavListItem
    title="Global parameters"
    description="Change instance-wide settings"
    href="/config/parameters"
/>
