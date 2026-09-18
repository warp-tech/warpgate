<script lang="ts">
    /**
     * Shared LDAP connection fields — restyled in place, used by both the
     * create and the edit screen.
     *
     * Behaviour preserved: every field and every binding, the password
     * placeholder and required flag that let the edit screen leave the
     * password blank to keep the existing one, the five username-attribute
     * choices, and the two attribute placeholders that document the defaults.
     *
     * Repointed at the migrated TlsConfiguration, which carries the warning
     * beneath the select when verification is disabled.
     */
    import { LdapUsernameAttribute, type Tls } from 'admin/lib/api'
    import TlsConfiguration from 'admin/screens/target-detail/TlsConfiguration.svelte'
    import Input from 'ui/Input.svelte'
    import 'ui/layout.css'
    import Select from 'ui/Select.svelte'

    interface Props {
        host: string
        port: number
        bindDn: string
        bindPassword: string
        tls: Tls
        userFilter: string
        passwordPlaceholder?: string
        passwordRequired?: boolean
        usernameAttribute: LdapUsernameAttribute
        sshKeyAttribute: string
        uuidAttribute: string
    }

    let {
        host = $bindable(),
        port = $bindable(),
        bindDn = $bindable(),
        bindPassword = $bindable(),
        usernameAttribute = $bindable(),
        sshKeyAttribute = $bindable(),
        uuidAttribute = $bindable(),
        tls = $bindable(),
        userFilter = $bindable(),
        passwordPlaceholder = undefined,
        passwordRequired = true,
    }: Props = $props()

    const usernameAttributeOptions = [
        { value: LdapUsernameAttribute.Cn, label: 'CN' },
        { value: LdapUsernameAttribute.Email, label: 'E-mail' },
        {
            value: LdapUsernameAttribute.UserPrincipalName,
            label: 'User principal name',
        },
        {
            value: LdapUsernameAttribute.SamAccountName,
            label: 'SAM account name',
        },
        { value: LdapUsernameAttribute.Uid, label: 'UID' },
    ]

    // ui/Input carries strings; port is a number on the model.
    const portText = $derived(String(port))
</script>

<div class="section">
    <div class="pair">
        <div class="grow">
            <Input label="Host" required mono bind:value={host} />
        </div>
        <div class="port">
            <Input
                label="Port"
                type="number"
                inputmode="numeric"
                min="1"
                max="65535"
                required
                value={portText}
                oninput={e => {
                    port = Number((e.target as HTMLInputElement).value)
                }}
            />
        </div>
    </div>

    <TlsConfiguration bind:value={tls} subject="this directory" />
</div>

<div class="section pair">
    <div class="grow">
        <Input label="Bind username / DN" required mono bind:value={bindDn} />
    </div>
    <div class="grow">
        <Input
            label="Bind password"
            type="password"
            autocomplete="off"
            placeholder={passwordPlaceholder}
            required={passwordRequired}
            bind:value={bindPassword}
        />
    </div>
</div>

<div class="section pair">
    <div class="grow">
        <Input
            label="User query filter"
            mono
            bind:value={userFilter}
            hint="Restricts which directory entries Warpgate will consider."
        />
    </div>
    <div class="grow wg-field-stack">
        <Select
            label="LDAP attribute to read usernames from"
            options={usernameAttributeOptions}
            bind:value={usernameAttribute}
        />
        <Input
            label="LDAP attribute to read SSH keys from"
            mono
            placeholder="sshPublicKey"
            bind:value={sshKeyAttribute}
        />
        <Input
            label="LDAP object UUID attribute"
            mono
            placeholder="Automatic (objectGUID / entryUUID)"
            bind:value={uuidAttribute}
        />
    </div>
</div>

<style>
    .section {
        margin-top: var(--wg-space-xl);
    }

    .pair {
        display: flex;
        align-items: flex-start;
        gap: var(--wg-space-lg);
        flex-wrap: wrap;
    }

    .grow {
        flex: 1 1 16rem;
        min-width: 0;
    }

    .port {
        flex: 0 1 8rem;
        min-width: 0;
    }
</style>
