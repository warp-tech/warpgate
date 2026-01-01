<script lang="ts" module>
    export type ExistingCredential =
        { kind: typeof CredentialKind.Password } & ExistingPasswordCredential
        | { kind: typeof CredentialKind.Sso } & ExistingSsoCredential
        | { kind: typeof CredentialKind.PublicKey } & ExistingPublicKeyCredential
        | { kind: typeof CredentialKind.Certificate } & ExistingCertificateCredential
        | { kind: typeof CredentialKind.Totp } & ExistingOtpCredential
</script>

<script lang="ts">
    import { faIdBadge, faKey, faKeyboard, faMobileScreen, faCertificate } from '@fortawesome/free-solid-svg-icons'
    import { api, CredentialKind, type ExistingPasswordCredential, type ExistingPublicKeyCredential, type ExistingSsoCredential, type ExistingOtpCredential, type ExistingCertificateCredential, type UserRequireCredentialsPolicy } from 'admin/lib/api'
    import Fa from 'svelte-fa'
    import { Button } from '@sveltestrap/sveltestrap'
    import CreatePasswordModal from './CreatePasswordModal.svelte'
    import SsoCredentialModal from './SsoCredentialModal.svelte'
    import PublicKeyCredentialModal from './PublicKeyCredentialModal.svelte'
    import CertificateCredentialModal from './CertificateCredentialModal.svelte'
    import CreateOtpModal from './CreateOtpModal.svelte'
    import AuthPolicyEditor from './AuthPolicyEditor.svelte'
    import { abbreviatePublicKey, possibleCredentials } from 'common/protocols'
    import CredentialUsedStateBadge from 'common/CredentialUsedStateBadge.svelte'
    import Loadable from 'common/Loadable.svelte'
    import EmptyState from 'common/EmptyState.svelte'
    import Tooltip from 'common/sveltestrap-s5-ports/Tooltip.svelte'

    interface Props {
        userId: string
        username: string
        credentialPolicy: UserRequireCredentialsPolicy,
        ldapLinked?: boolean
    }
    let { userId, username, credentialPolicy = $bindable(), ldapLinked = false }: Props = $props()

    let credentials: ExistingCredential[] = $state([])

    let creatingPassword = $state(false)
    let creatingOtp = $state(false)
    let editingSsoCredential = $state(false)
    let editingSsoCredentialInstance: ExistingSsoCredential|null = $state(null)
    let editingPublicKeyCredential = $state(false)
    let editingPublicKeyCredentialInstance: ExistingPublicKeyCredential|null = $state(null)
    let editingCertificateCredential = $state(false)

    const loadPromise = load()

    const policyProtocols: { id: 'ssh' | 'http' | 'mysql' | 'postgres' | 'kubernetes', name: string }[] = [
        { id: 'ssh', name: 'SSH' },
        { id: 'http', name: 'HTTP' },
        { id: 'mysql', name: 'MySQL' },
        { id: 'postgres', name: 'PostgreSQL' },
        { id: 'kubernetes', name: 'Kubernetes' },
    ]

    async function load () {
        await Promise.all([
            loadPasswords(),
            loadSso(),
            loadPublicKeys(),
            loadCertificates(),
            loadOtp(),
        ])
    }

    async function loadPasswords () {
        credentials.push(...(await api.getPasswordCredentials({ userId })).map(c => ({
            kind: CredentialKind.Password,
            ...c,
        })))
    }

    async function loadSso () {
        credentials.push(...(await api.getSsoCredentials({ userId })).map(c => ({
            kind: CredentialKind.Sso,
            ...c,
        })))
    }

    async function loadPublicKeys () {
        credentials.push(...(await api.getPublicKeyCredentials({ userId })).map(c => ({
            kind: CredentialKind.PublicKey,
            ...c,
        })))
    }

    async function loadCertificates () {
        credentials.push(...(await api.getCertificateCredentials({ userId })).map(c => ({
            kind: CredentialKind.Certificate,
            ...c,
        })))
    }

    async function loadOtp () {
        credentials.push(...(await api.getOtpCredentials({ userId })).map(c => ({
            kind: CredentialKind.Totp,
            ...c,
        })))
    }

    async function deleteCredential (credential: ExistingCredential) {
        credentials = credentials.filter(c => c !== credential)
        if (credential.kind === CredentialKind.Password) {
            await api.deletePasswordCredential({
                id: credential.id,
                userId,
            })
        }
        if (credential.kind === CredentialKind.Sso) {
            await api.deleteSsoCredential({
                id: credential.id,
                userId,
            })
        }
        if (credential.kind === CredentialKind.PublicKey) {
            await api.deletePublicKeyCredential({
                id: credential.id,
                userId,
            })
        }
        if (credential.kind === CredentialKind.Certificate) {
            if (confirm('Permanently revoke certificate?')) {
                await api.revokeCertificateCredential({
                    id: credential.id,
                    userId,
                })
            }
        }
        if (credential.kind === CredentialKind.Totp) {
            await api.deleteOtpCredential({
                id: credential.id,
                userId,
            })
        }
    }

    async function createPassword (password: string) {
        const credential = await api.createPasswordCredential({
            userId,
            newPasswordCredential: {
                password,
            },
        })
        credentials.push({
            kind: CredentialKind.Password,
            ...credential,
        })
    }

    async function createOtp (secretKey: number[]) {
        const credential = await api.createOtpCredential({
            userId,
            newOtpCredential: {
                secretKey,
            },
        })
        credentials.push({
            kind: CredentialKind.Totp,
            ...credential,
        })

        // Automatically set up a 2FA policy when adding an OTP
        for (const protocol of ['http', 'ssh'] as ('http'|'ssh')[]) {
            for (const ck of [CredentialKind.Password, CredentialKind.PublicKey]) {
                if (
                    !credentialPolicy[protocol]
                    && credentials.some(x => x.kind === ck)
                    && possibleCredentials[protocol]?.has(ck)
                ) {
                    credentialPolicy = {
                        ...credentialPolicy ?? {},
                        [protocol]: [ck, CredentialKind.Totp],
                    }
                }
            }
        }
    }

    async function saveSsoCredential (provider: string|null, email: string) {
        if (editingSsoCredentialInstance) {
            editingSsoCredentialInstance.provider = provider ?? undefined
            editingSsoCredentialInstance.email = email
            await api.updateSsoCredential({
                userId,
                id: editingSsoCredentialInstance.id,
                newSsoCredential: editingSsoCredentialInstance,
            })
        } else {
            const credential = await api.createSsoCredential({
                userId,
                newSsoCredential: {
                    provider:provider ?? undefined,
                    email,
                },
            })
            credentials.push({
                kind: CredentialKind.Sso,
                ...credential,
            })
        }
        editingSsoCredential = false
        editingSsoCredentialInstance = null
    }

    async function savePublicKeyCredential (label: string, opensshPublicKey: string) {
        if (editingPublicKeyCredentialInstance) {
            editingPublicKeyCredentialInstance.label = label
            editingPublicKeyCredentialInstance.opensshPublicKey = opensshPublicKey
            await api.updatePublicKeyCredential({
                userId,
                id: editingPublicKeyCredentialInstance.id,
                newPublicKeyCredential: editingPublicKeyCredentialInstance,
            })
        } else {
            const credential = await api.createPublicKeyCredential({
                userId,
                newPublicKeyCredential: {
                    label,
                    opensshPublicKey,
                },
            })
            credentials.push({
                kind: CredentialKind.PublicKey,
                ...credential,
            })
        }
        editingPublicKeyCredential = false
        editingPublicKeyCredentialInstance = null
    }

    async function saveCertificateCredential (label: string, publicKeyPem: string) {
        const response = await api.issueCertificateCredential({
            userId,
            issueCertificateCredentialRequest: {
                label,
                publicKeyPem,
            },
        })

        credentials.push({
            kind: CredentialKind.Certificate,
            ...response.credential,
        })

        return response
    }

    function assertDefined<T>(value: T|undefined): T {
        if (value === undefined) {
            throw new Error('Value is undefined')
        }
        return value
    }
</script>

<div class="d-flex align-items-center mt-4 mb-2">
    <h4 class="m-0">Credentials</h4>
    <span class="ms-auto"></span>
    <Button size="sm" color="link" on:click={() => creatingPassword = true}>
        Add password
    </Button>
    <Button size="sm" color="link" on:click={() => {
        editingCertificateCredential = true
    }}>Issue certificate</Button>
    <Button
        id="addPublicKeyCredentialButton"
        size="sm"
        color="link"
        on:click={() => {
            if (ldapLinked) {
                return
            }
            editingPublicKeyCredentialInstance = null
            editingPublicKeyCredential = true
        }}
        title={ldapLinked ? 'SSH keys are managed by LDAP' : ''}
    >Add public key</Button>
    <Tooltip delay="250" target="addPublicKeyCredentialButton" animation>Public key credentials will be loaded from LDAP</Tooltip>

    <Button size="sm" color="link" on:click={() => creatingOtp = true}>Add OTP</Button>
    <Button size="sm" color="link" on:click={() => {
        editingSsoCredentialInstance = null
        editingSsoCredential = true
    }}>Add SSO</Button>
</div>

<Loadable promise={loadPromise}>
    {#if credentials.length === 0}
        <EmptyState
            title="No credentials added"
            hint="Users need credentials to authenticate with Warpgate"
        />
    {/if}
    <div class="list-group list-group-flush mb-3">
        {#each credentials as credential (credential.id)}
        <div class="list-group-item credential gap-2">
            {#if credential.kind === CredentialKind.Password }
                <Fa fw icon={faKeyboard} />
                <span class="label me-auto">Password</span>
            {/if}
            {#if credential.kind === 'PublicKey'}
                <Fa fw icon={faKey} />
                <div class="main me-auto">
                    <div class="label d-flex align-items-center">
                        {credential.label}
                    </div>
                    <small class="d-block text-muted">{abbreviatePublicKey(credential.opensshPublicKey)}</small>
                </div>
                <CredentialUsedStateBadge credential={credential} />
            {/if}
            {#if credential.kind === CredentialKind.Certificate}
                <Fa fw icon={faCertificate} />
                <div class="main me-auto abbreviate">
                    <div class="label d-flex align-items-center">
                        {credential.label}
                    </div>
                    <small class="d-block text-muted abbreviate">SHA-256: <code>{credential.fingerprint}</code></small>
                </div>
                <CredentialUsedStateBadge credential={credential} />
            {/if}
            {#if credential.kind === 'Totp'}
                <Fa fw icon={faMobileScreen} />
                <span class="label me-auto">One-time password</span>
            {/if}
            {#if credential.kind === CredentialKind.Sso}
                <Fa fw icon={faIdBadge} />
                <span class="label">Single sign-on</span>
                <span class="text-muted me-auto">
                    {credential.email}
                    {#if credential.provider} ({credential.provider}){/if}
                </span>
            {/if}

            {#if credential.kind === CredentialKind.PublicKey || credential.kind === CredentialKind.Sso}
            <Button
                class="px-0"
                color="link"
                disabled={credential.kind === CredentialKind.PublicKey && ldapLinked}
                onclick={e => {
                    if (credential.kind === CredentialKind.Sso) {
                        editingSsoCredentialInstance = credential
                        editingSsoCredential = true
                    }
                    if (credential.kind === CredentialKind.PublicKey) {
                        editingPublicKeyCredentialInstance = credential
                        editingPublicKeyCredential = true
                    }
                    e.preventDefault()
                }}>
                Change
            </Button>
            {/if}
            <Button
                class="px-0"
                color="link"
                disabled={credential.kind === CredentialKind.PublicKey && ldapLinked}
                onclick={e => {
                    deleteCredential(credential)
                    e.preventDefault()
                }}>
                Delete
            </Button>
        </div>
        {/each}
    </div>

    <h4>Auth policy</h4>
    <div class="list-group list-group-flush mb-3">
        {#each policyProtocols as protocol (protocol)}
        <div class="list-group-item">
            <div class="mb-1">
                <strong>{protocol.name}</strong>
            </div>
            {#if possibleCredentials[protocol.id]}
                {@const _possibleCredentials = assertDefined(possibleCredentials[protocol.id])}
                <AuthPolicyEditor
                    bind:value={credentialPolicy}
                    existingCredentials={credentials}
                    possibleCredentials={_possibleCredentials}
                    protocolId={protocol.id}
                />
            {/if}
        </div>
        {/each}
    </div>
</Loadable>

{#if creatingPassword}
<CreatePasswordModal
    bind:isOpen={creatingPassword}
    create={createPassword}
/>
{/if}

{#if creatingOtp}
<CreateOtpModal
    bind:isOpen={creatingOtp}
    {username}
    create={createOtp}
/>
{/if}

{#if editingSsoCredential}
<SsoCredentialModal
    bind:isOpen={editingSsoCredential}
    instance={editingSsoCredentialInstance}
    save={saveSsoCredential}
/>
{/if}

{#if editingPublicKeyCredential}
<PublicKeyCredentialModal
    bind:isOpen={editingPublicKeyCredential}
    instance={editingPublicKeyCredentialInstance ?? undefined}
    save={savePublicKeyCredential}
/>
{/if}

{#if editingCertificateCredential}
<CertificateCredentialModal
    bind:isOpen={editingCertificateCredential}
    save={saveCertificateCredential}
    {username}
    onClose={() => {
        editingCertificateCredential = false
    }}
/>
{/if}

<style lang="scss">
    .credential {
        display: flex;
        align-items: center;

        .label:not(:first-child), .main {
            margin-left: .75rem;
        }
    }
</style>
