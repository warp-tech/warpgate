<script lang="ts" module>
    const kinds = {
        Target: 'target',
        TargetGroup: 'target group',
        Role: 'access role',
        SshClientKey: 'SSH client key',
        User: 'user',
        AdminRole: 'admin role',
        LdapServer: 'LDAP server',
        SecretBackend: 'secret backend',
        KnownHost: 'SSH known host',
        Parameters: 'parameters',
    }

    export interface ResourceChanged1 {
        _type: 'ResourceChanged1'
        action: 'Create' | 'Update' | 'Adopt' | 'Delete'
        kind: keyof typeof kinds
        id: string
        name: string
        /** JSON array of the changed fields */
        fields?: string
        /** Present for a change made by a sync */
        provider?: string
    }
</script>

<script lang="ts">
    import AccessRoleBadge from './AccessRoleBadge.svelte'
    import AdminRoleBadge from './AdminRoleBadge.svelte'
    import TargetBadge from './TargetBadge.svelte'
    import UserBadge from './UserBadge.svelte'

    interface Field {
        path: string
        credential?: boolean
        from?: unknown
        to?: unknown
    }

    let { entry }: { entry: ResourceChanged1 } = $props()

    const verbs = {
        Create: 'Created',
        Update: 'Updated',
        Adopt: 'Adopted',
        Delete: 'Deleted',
    }

    let fields = $derived.by((): Field[] => {
        try {
            const parsed: unknown = JSON.parse(entry.fields ?? '[]')
            return Array.isArray(parsed) ? parsed : []
        } catch {
            return []
        }
    })

    // A deleted resource has no page to link to
    let linked = $derived(entry.action !== 'Delete')
    // A new resource's fields have no earlier value
    let created = $derived(entry.action === 'Create')

    function show(value: unknown): string {
        return value == null ? 'none' : JSON.stringify(value)
    }
</script>

{verbs[entry.action]}
{kinds[entry.kind]}
{#if linked && entry.kind === 'Target'}
    <TargetBadge id={entry.id} name={entry.name} />
{:else if linked && entry.kind === 'Role'}
    <AccessRoleBadge id={entry.id} name={entry.name} />
{:else if linked && entry.kind === 'User'}
    <UserBadge id={entry.id} name={entry.name} />
{:else if linked && entry.kind === 'AdminRole'}
    <AdminRoleBadge id={entry.id} name={entry.name} />
{:else if entry.name}
    <strong>{entry.name}</strong>
{/if}
{#each fields as field (field.path)}
    <span>
        <span class="text-secondary fst-italic">{field.path}</span>
        {#if field.credential}
            {created ? 'set' : 'changed'}
        {:else if created}
            {show(field.to)}
        {:else}
            {show(field.from)}
            → {show(field.to)}
        {/if}
    </span>
{/each}
{#if entry.provider}
    <span class="badge bg-secondary">{entry.provider}</span>
{/if}
