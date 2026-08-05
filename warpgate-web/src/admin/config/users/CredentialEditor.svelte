<script lang="ts" module>
    export type ExistingCredential =
        | ({
              kind: typeof CredentialKind.Password
          } & ExistingPasswordCredential)
        | ({ kind: typeof CredentialKind.Sso } & ExistingSsoCredential)
        | ({
              kind: typeof CredentialKind.PublicKey
          } & ExistingPublicKeyCredential)
        | ({
              kind: typeof CredentialKind.Certificate
          } & ExistingCertificateCredential)
        | ({ kind: typeof CredentialKind.Totp } & ExistingOtpCredential)
        | ({
              kind: typeof CredentialKind.WebAuthn
          } & ExistingWebauthnCredential)
</script>

<script lang="ts">
    import {
        faCertificate,
        faFingerprint,
        faIdBadge,
        faKey,
        faKeyboard,
        faMobileScreen,
    } from '@fortawesome/free-solid-svg-icons'
    import { Button, Tooltip } from '@sveltestrap/sveltestrap'
    import {
        api,
        CredentialKind,
        type ExistingCertificateCredential,
        type ExistingOtpCredential,
        type ExistingPasswordCredential,
        type ExistingPublicKeyCredential,
        type ExistingSsoCredential,
        type ExistingWebauthnCredential,
        type ParameterValues,
        type UserRequireCredentialsPolicy,
    } from 'admin/lib/api'
    import { adminPermissions } from 'admin/lib/store'
    import CredentialUsedStateBadge from 'common/CredentialUsedStateBadge.svelte'
    import EmptyState from 'common/EmptyState.svelte'
    import Loadable from 'common/Loadable.svelte'
    import { abbreviatePublicKey, possibleCredentials } from 'common/protocols'
    import { api as gatewayApi } from 'gateway/lib/api'
    import { serverInfo } from 'gateway/lib/store'
    import { SvelteSet } from 'svelte/reactivity'
    import Fa from 'svelte-fa'
    import CertificateCredentialModal from '../../CertificateCredentialModal.svelte'
    import CreateOtpModal from '../../CreateOtpModal.svelte'
    import CreatePasswordModal from '../../CreatePasswordModal.svelte'
    import PublicKeyCredentialModal from '../../PublicKeyCredentialModal.svelte'
    import SsoCredentialModal from '../../SsoCredentialModal.svelte'
    import WebauthnCredentialModal from '../../WebauthnCredentialModal.svelte'
    import AuthPolicyEditor from './AuthPolicyEditor.svelte'

    interface Props {
        userId: string
        username: string
        credentialPolicy: UserRequireCredentialsPolicy
        ldapLinked?: boolean
    }
    let {
        userId,
        username,
        credentialPolicy = $bindable(),
        ldapLinked = false,
    }: Props = $props()

    let credentials: ExistingCredential[] = $state([])
    const isOwnUser = $derived($serverInfo?.username === username)
    let globalParameters: ParameterValues | undefined = $state()

    let creatingPassword = $state(false)
    let creatingOtp = $state(false)
    let creatingWebauthn = $state(false)
    let editingSsoCredential = $state(false)
    let editingSsoCredentialInstance: ExistingSsoCredential | null =
        $state(null)
    let editingPublicKeyCredential = $state(false)
    let editingPublicKeyCredentialInstance: ExistingPublicKeyCredential | null =
        $state(null)
    let editingCertificateCredential = $state(false)

    const loadPromise = load()

    const policyProtocols: {
        id: 'ssh' | 'http' | 'mysql' | 'postgres' | 'kubernetes' | 'vnc' | 'rdp'
        name: string
    }[] = [
        { id: 'ssh', name: 'SSH' },
        { id: 'http', name: 'HTTP' },
        { id: 'mysql', name: 'MySQL' },
        { id: 'postgres', name: 'PostgreSQL' },
        { id: 'kubernetes', name: 'Kubernetes' },
        { id: 'vnc', name: 'VNC' },
        { id: 'rdp', name: 'RDP' },
    ]

    // Get effective possible credentials for a protocol, considering global SSH auth settings
    function getEffectivePossibleCredentials(
        protocolId: string,
    ): SvelteSet<CredentialKind> {
        const base = possibleCredentials[protocolId]
        if (!base) {
            return new SvelteSet()
        }

        // For SSH, filter based on global auth method settings
        if (protocolId === 'ssh' && globalParameters) {
            const filtered = new SvelteSet<CredentialKind>()
            for (const kind of base) {
                // PublicKey requires publickey auth enabled
                if (
                    kind === CredentialKind.PublicKey &&
                    !globalParameters.sshClientAuthPublickey
                ) {
                    continue
                }
                // Password requires password auth enabled
                if (
                    kind === CredentialKind.Password &&
                    !globalParameters.sshClientAuthPassword
                ) {
                    continue
                }
                // Totp and WebUserApproval require keyboard-interactive auth enabled
                if (
                    (kind === CredentialKind.Totp ||
                        kind === CredentialKind.WebUserApproval) &&
                    !globalParameters.sshClientAuthKeyboardInteractive
                ) {
                    continue
                }
                filtered.add(kind)
            }
            return filtered
        }

        return new SvelteSet(base)
    }

    async function load() {
        await Promise.all([
            loadPasswords(),
            loadSso(),
            loadPublicKeys(),
            loadCertificates(),
            loadOtp(),
            loadWebauthn(),
            loadParameters(),
        ])
    }

    async function loadParameters() {
        globalParameters = await api.getParameters({})
    }

    async function loadPasswords() {
        credentials.push(
            ...(await api.getPasswordCredentials({ userId })).map(c => ({
                kind: CredentialKind.Password,
                ...c,
            })),
        )
    }

    async function loadSso() {
        credentials.push(
            ...(await api.getSsoCredentials({ userId })).map(c => ({
                kind: CredentialKind.Sso,
                ...c,
            })),
        )
    }

    async function loadPublicKeys() {
        credentials.push(
            ...(await api.getPublicKeyCredentials({ userId })).map(c => ({
                kind: CredentialKind.PublicKey,
                ...c,
            })),
        )
    }

    async function loadCertificates() {
        credentials.push(
            ...(await api.getCertificateCredentials({ userId })).map(c => ({
                kind: CredentialKind.Certificate,
                ...c,
            })),
        )
    }

    async function loadOtp() {
        credentials.push(
            ...(await api.getOtpCredentials({ userId })).map(c => ({
                kind: CredentialKind.Totp,
                ...c,
            })),
        )
    }

    async function loadWebauthn() {
        credentials.push(
            ...(await api.getWebauthnCredentials({ userId })).map(c => ({
                kind: CredentialKind.WebAuthn,
                ...c,
            })),
        )
    }

    async function deleteCredential(credential: ExistingCredential) {
        if (credential.kind === CredentialKind.Certificate) {
            if (
                !confirm(
                    'Permanently revoke certificate? This cannot be undone.',
                )
            ) {
                return
            }
        }
        if (credential.kind === CredentialKind.WebAuthn) {
            if (
                !confirm(
                    'Delete this passkey? The user will need to re-register it.',
                )
            ) {
                return
            }
        }

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
            await api.revokeCertificateCredential({
                id: credential.id,
                userId,
            })
        }
        if (credential.kind === CredentialKind.Totp) {
            await api.deleteOtpCredential({
                id: credential.id,
                userId,
            })
        }
        if (credential.kind === CredentialKind.WebAuthn) {
            await api.deleteWebauthnCredential({
                id: credential.id,
                userId,
            })
        }

        // If the user has no more credentials of this kind, remove it from the policy
        const remainingOfKind = credentials.filter(
            c => c.kind === credential.kind,
        )
        if (remainingOfKind.length === 0) {
            for (const protocol of [
                'http',
                'ssh',
                'mysql',
                'postgres',
                'kubernetes',
                'vnc',
                'rdp',
            ] as const) {
                if (credentialPolicy[protocol]?.includes(credential.kind)) {
                    credentialPolicy = {
                        ...credentialPolicy,
                        [protocol]:
                            credentialPolicy[protocol]?.filter(
                                k => k !== credential.kind,
                            ) ?? [],
                    }
                }
            }
        }
    }

    async function createPassword(password: string) {
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

    async function createOtp(secretKey: number[]) {
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
        for (const protocol of ['http', 'ssh'] as ('http' | 'ssh')[]) {
            for (const ck of [
                CredentialKind.Password,
                CredentialKind.PublicKey,
            ]) {
                const effectiveCreds = getEffectivePossibleCredentials(protocol)
                if (
                    !credentialPolicy[protocol] &&
                    credentials.some(x => x.kind === ck) &&
                    effectiveCreds.has(ck)
                ) {
                    credentialPolicy = {
                        ...(credentialPolicy ?? {}),
                        [protocol]: [ck, CredentialKind.Totp],
                    }
                }
            }
        }
    }

    async function saveSsoCredential(provider: string | null, email: string) {
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
                    provider: provider ?? undefined,
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

    async function savePublicKeyCredential(
        label: string,
        opensshPublicKey: string,
    ) {
        if (editingPublicKeyCredentialInstance) {
            editingPublicKeyCredentialInstance.label = label
            editingPublicKeyCredentialInstance.opensshPublicKey =
                opensshPublicKey
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

    async function saveCertificateCredential(
        label: string,
        publicKeyPem: string,
    ) {
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

    function base64UrlToBuffer(base64url: string): ArrayBuffer {
        const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/')
        const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4)
        const binary = atob(padded)
        const bytes = new Uint8Array(binary.length)
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i)
        }
        return bytes.buffer
    }

    function bufferToBase64Url(buffer: ArrayBuffer): string {
        const bytes = new Uint8Array(buffer)
        let binary = ''
        for (const byte of bytes) {
            binary += String.fromCharCode(byte)
        }
        return btoa(binary)
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '')
    }
</script>

<div class="d-flex mt-4 mb-2 header">
    <h4 class="m-0">Credentials</h4>
    <span class="ms-auto"></span>
    {#if $adminPermissions.usersEdit}
        <Button size="sm" color="link" on:click={() => creatingPassword = true}>
            Add password
        </Button>
        <Button
            size="sm"
            color="link"
            on:click={() => {
                editingCertificateCredential = true
            }}
        >
            Issue certificate
        </Button>
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
        >
            Add public key
        </Button>
        <Tooltip delay="250" target="addPublicKeyCredentialButton" animation>
            Public key credentials will be loaded from LDAP
        </Tooltip>

        <Button size="sm" color="link" on:click={() => creatingOtp = true}>
            Add OTP
        </Button>
        {#if isOwnUser}
            <Button
                size="sm"
                color="link"
                on:click={() => creatingWebauthn = true}
            >
                Add passkey
            </Button>
        {/if}
        <Button
            size="sm"
            color="link"
            on:click={() => {
        editingSsoCredentialInstance = null
        editingSsoCredential = true
    }}
        >
            Add SSO
        </Button>
    {/if}
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
                {#if credential.kind === CredentialKind.Password}
                    <Fa fw icon={faKeyboard} />
                    <span class="label me-auto">Password</span>
                {/if}
                {#if credential.kind === 'PublicKey'}
                    <Fa fw icon={faKey} />
                    <div class="main me-auto">
                        <div class="label d-flex align-items-center">
                            {credential.label}
                        </div>
                        <small class="d-block text-muted"
                            >{abbreviatePublicKey(credential.opensshPublicKey)}</small
                        >
                    </div>
                    <CredentialUsedStateBadge {credential} />
                {/if}
                {#if credential.kind === CredentialKind.Certificate}
                    <Fa fw icon={faCertificate} />
                    <div class="main me-auto abbreviate">
                        <div class="label d-flex align-items-center">
                            {credential.label}
                        </div>
                        <small class="d-block text-muted abbreviate">
                            SHA-256:
                            <code>{credential.fingerprint}</code>
                        </small>
                    </div>
                    <CredentialUsedStateBadge {credential} />
                {/if}
                {#if credential.kind === 'Totp'}
                    <Fa fw icon={faMobileScreen} />
                    <span class="label me-auto">One-time password</span>
                {/if}
                {#if credential.kind === CredentialKind.WebAuthn}
                    <Fa fw icon={faFingerprint} />
                    <div class="main me-auto">
                        <div class="label d-flex align-items-center">
                            {credential.label}
                        </div>
                    </div>
                    <CredentialUsedStateBadge {credential} />
                {/if}
                {#if credential.kind === CredentialKind.Sso}
                    <Fa fw icon={faIdBadge} />
                    <span class="label">Single sign-on</span>
                    <span class="text-muted me-auto">
                        {credential.email}
                        {#if credential.provider}
                            ({credential.provider})
                        {/if}
                    </span>
                {/if}

                {#if credential.kind === CredentialKind.PublicKey || credential.kind === CredentialKind.Sso}
                    <Button
                        class="px-0"
                        color="link"
                        disabled={credential.kind === CredentialKind.PublicKey && (ldapLinked || !$adminPermissions.usersEdit)}
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
                }}
                    >
                        Change
                    </Button>
                {/if}
                <Button
                    class="px-0"
                    color="link"
                    disabled={credential.kind === CredentialKind.PublicKey && (ldapLinked || !$adminPermissions.usersEdit)}
                    onclick={e => {
                    deleteCredential(credential)
                    e.preventDefault()
                }}
                >
                    Delete
                </Button>
            </div>
        {/each}
    </div>

    <h4>Auth policy</h4>
    <div class="list-group list-group-flush mb-3">
        {#each policyProtocols as protocol (protocol)}
            {@const effectiveCredentials = getEffectivePossibleCredentials(protocol.id)}
            <div class="list-group-item">
                <div class="mb-1">
                    <strong>{protocol.name}</strong>
                </div>
                {#if effectiveCredentials.size > 0 || credentialPolicy[protocol.id]?.length}
                    <AuthPolicyEditor
                        bind:value={credentialPolicy}
                        existingCredentials={credentials}
                        possibleCredentials={effectiveCredentials}
                        protocolId={protocol.id}
                    />
                {:else}
                    <span class="text-muted">
                        No authentication methods available for this protocol
                    </span>
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
    <CreateOtpModal bind:isOpen={creatingOtp} {username} create={createOtp} />
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

{#if creatingWebauthn}
    <WebauthnCredentialModal
        bind:isOpen={creatingWebauthn}
        {userId}
        save={async (label, signal) => {
            if (credentials.some(c => c.kind === CredentialKind.WebAuthn && c.label === label)) {
                throw new Error('A passkey with this name already exists')
            }

            const startResp = await gatewayApi.startWebauthnRegistration()
            const challengeOptions = JSON.parse(startResp.challengeJson)

            const pubKey = challengeOptions.publicKey
            pubKey.challenge = base64UrlToBuffer(pubKey.challenge)
            pubKey.user.id = base64UrlToBuffer(pubKey.user.id)
            if (pubKey.excludeCredentials) {
                pubKey.excludeCredentials = pubKey.excludeCredentials.map((c: { id: string }) => ({
                    ...c,
                    id: base64UrlToBuffer(c.id),
                }))
            }

            let credential: PublicKeyCredential
            try {
                const result = await navigator.credentials.create({ publicKey: pubKey, signal })
                if (!result) throw new Error('Registration was cancelled')
                credential = result as PublicKeyCredential
            } catch (e: unknown) {
                if (e instanceof DOMException && (e.name === 'NotAllowedError' || e.name === 'AbortError')) {
                    throw e
                }
                throw e
            }

            const response = credential.response as AuthenticatorAttestationResponse
            const credentialJson = JSON.stringify({
                id: credential.id,
                rawId: bufferToBase64Url(credential.rawId),
                type: credential.type,
                response: {
                    attestationObject: bufferToBase64Url(response.attestationObject),
                    clientDataJSON: bufferToBase64Url(response.clientDataJSON),
                    transports: response.getTransports ? response.getTransports() : [],
                },
            })

            const result = await gatewayApi.completeWebauthnRegistration({
                registrationCompleteRequest: { credentialJson, label },
            })
            credentials.push({ kind: CredentialKind.WebAuthn, id: result.id, label: result.label, dateAdded: new Date(), lastUsed: undefined })

            // Automatically set up a 2FA policy when adding a passkey
            for (const protocol of ['http', 'ssh'] as ('http' | 'ssh')[]) {
                for (const ck of [
                    CredentialKind.Password,
                    CredentialKind.PublicKey,
                ]) {
                    const effectiveCreds = getEffectivePossibleCredentials(protocol)
                    if (
                        !credentialPolicy[protocol] &&
                        credentials.some(x => x.kind === ck) &&
                        effectiveCreds.has(ck)
                    ) {
                        credentialPolicy = {
                            ...(credentialPolicy ?? {}),
                            [protocol]: [ck, CredentialKind.WebAuthn],
                        }
                    }
                }
            }
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

    .header {
        align-items: center;
    }

    @media (max-width: 720px) {
        .header {
            flex-direction: column;
            align-items: start;
        }
    }
</style>
