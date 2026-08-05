<script lang="ts">
    import {
        faCertificate,
        faFingerprint,
        faIdBadge,
        faKey,
        faKeyboard,
        faMobilePhone,
    } from '@fortawesome/free-solid-svg-icons'
    import { Alert, Button, Tooltip } from '@sveltestrap/sveltestrap'
    import CertificateCredentialModal from 'admin/CertificateCredentialModal.svelte'
    import CreateOtpModal from 'admin/CreateOtpModal.svelte'
    import CreatePasswordModal from 'admin/CreatePasswordModal.svelte'
    import PublicKeyCredentialModal from 'admin/PublicKeyCredentialModal.svelte'
    import WebauthnCredentialModal from 'admin/WebauthnCredentialModal.svelte'
    import CredentialUsedStateBadge from 'common/CredentialUsedStateBadge.svelte'
    import Loadable from 'common/Loadable.svelte'
    import {
        api,
        CredentialKind,
        type CredentialsState,
        type ExistingCertificateCredential,
        type ExistingOtpCredential,
        type ExistingPublicKeyCredential,
        type ExistingWebauthnCredentialSelf,
        PasswordState,
    } from 'gateway/lib/api'
    import { deleteCertificateKey } from 'gateway/lib/certificateStore'
    import { serverInfo } from 'gateway/lib/store'
    import Fa from 'svelte-fa'

    let creds: CredentialsState | undefined = $state()

    let creatingPublicKeyCredential = $state(false)
    let issuingCertificateCredential = $state(false)
    let creatingOtpCredential = $state(false)
    let changingPassword = $state(false)
    let registeringWebauthn = $state(false)
    let webauthnError: string | null = $state(null)
    let creatingWebauthn = $state(false)

    const initPromise = init()

    async function init() {
        creds = await api.getMyCredentials()
    }

    async function changePassword(password: string) {
        if (!creds) {
            return
        }
        const state = await api.changeMyPassword({
            changePasswordRequest: { password },
        })
        creds.password = state
    }

    async function createPublicKey(label: string, opensshPublicKey: string) {
        if (!creds) {
            return
        }
        const credential = await api.addMyPublicKey({
            newPublicKeyCredential: {
                label,
                opensshPublicKey,
            },
        })
        creds.publicKeys.push(credential)
    }

    async function deletePublicKey(credential: ExistingPublicKeyCredential) {
        if (!creds) {
            return
        }
        creds.publicKeys = creds.publicKeys.filter(c => c.id !== credential.id)
        await api.deleteMyPublicKey(credential)
    }

    async function createOtp(secretKey: number[]) {
        if (!creds) {
            return
        }
        const credential = await api.addMyOtp({
            newOtpCredential: {
                secretKey,
            },
        })
        creds.otp.push(credential)
    }

    async function deleteOtp(credential: ExistingOtpCredential) {
        if (!creds) {
            return
        }
        creds.otp = creds.otp.filter(c => c.id !== credential.id)
        await api.deleteMyOtp(credential)
    }

    async function issueCertificate(label: string, publicKeyPem: string) {
        const response = await api.issueMyCertificate({
            issueCertificateCredentialRequest: {
                label,
                publicKeyPem,
            },
        })
        if (creds) {
            creds.certificates.push(response.credential)
        }
        return response
    }

    async function deleteCertificate(
        credential: ExistingCertificateCredential,
    ) {
        if (!creds) {
            return
        }
        if (confirm('Permanently revoke certificate?')) {
            creds.certificates = creds.certificates.filter(
                c => c.id !== credential.id,
            )
            await api.revokeMyCertificate(credential)
            await deleteCertificateKey(credential.id)
        }
    }

    async function registerWebauthn(label: string, signal: AbortSignal) {
        if (!creds) return
        if (creds.webauthn.some(c => c.label === label)) {
            throw new Error('A passkey with this name already exists')
        }
        webauthnError = null
        registeringWebauthn = true
        try {
            // Start registration ceremony
            const startResp = await api.startWebauthnRegistration()
            const challengeOptions = JSON.parse(startResp.challengeJson)

            // Call the browser's WebAuthn API
            let credential: PublicKeyCredential | null
            try {
                credential = (await navigator.credentials.create({
                    publicKey: {
                        ...challengeOptions.publicKey,
                        challenge: base64UrlToBuffer(
                            challengeOptions.publicKey.challenge,
                        ),
                        user: {
                            ...challengeOptions.publicKey.user,
                            id: base64UrlToBuffer(
                                challengeOptions.publicKey.user.id,
                            ),
                        },
                        excludeCredentials: (
                            challengeOptions.publicKey.excludeCredentials ?? []
                        ).map((c: { id: string }) => ({
                            ...c,
                            id: base64UrlToBuffer(c.id),
                        })),
                    },
                    signal,
                })) as PublicKeyCredential | null
            } catch (domErr: unknown) {
                if (
                    domErr instanceof DOMException &&
                    (domErr.name === 'NotAllowedError' ||
                        domErr.name === 'AbortError')
                ) {
                    // User cancelled — no error needed
                    return
                }
                throw domErr
            }

            if (!credential) {
                return
            }

            const response =
                credential.response as AuthenticatorAttestationResponse
            const credentialJson = JSON.stringify({
                id: credential.id,
                rawId: bufferToBase64Url(credential.rawId),
                type: credential.type,
                response: {
                    attestationObject: bufferToBase64Url(
                        response.attestationObject,
                    ),
                    clientDataJSON: bufferToBase64Url(response.clientDataJSON),
                    transports: response.getTransports
                        ? response.getTransports()
                        : [],
                },
            })

            // Complete registration
            const result = await api.completeWebauthnRegistration({
                registrationCompleteRequest: {
                    credentialJson,
                    label,
                },
            })

            creds.webauthn.push({
                id: result.id,
                label: result.label,
                dateAdded: new Date(),
                lastUsed: undefined,
            })
        } catch (e: unknown) {
            webauthnError =
                e instanceof Error ? e.message : 'Registration failed'
        } finally {
            registeringWebauthn = false
        }
    }

    async function deleteWebauthn(credential: ExistingWebauthnCredentialSelf) {
        if (!creds) return
        if (!confirm('Delete this passkey? You will need to re-register it.'))
            return
        creds.webauthn = creds.webauthn.filter(c => c.id !== credential.id)
        await api.deleteMyWebauthnCredential(credential)
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

<Loadable promise={initPromise}>
    {#if creds}
        <div class="d-flex align-items-center mt-4 mb-2">
            <h4 class="m-0">Password</h4>
        </div>

        <div class="list-group list-group-flush mb-3">
            <div class="list-group-item credential">
                {#if creds.password === PasswordState.Unset}
                    <span class="label ms-3">
                        Your account has no password set
                    </span>
                {/if}
                {#if creds.password === PasswordState.Set}
                    <Fa fw icon={faKeyboard} />
                    <span class="label ms-3">Password set</span>
                {/if}
                {#if creds.password === PasswordState.MultipleSet}
                    <Fa fw icon={faKeyboard} />
                    <span class="label ms-3">Multiple passwords set</span>
                {/if}

                <span class="ms-auto"></span>
                <Button
                    class="ms-2"
                    color="link"
                    onclick={e => {
                    changingPassword = true
                    e.preventDefault()
                }}
                >
                    {#if creds.password === PasswordState.Unset}
                        Set password
                    {/if}
                    {#if creds.password === PasswordState.Set}
                        Change
                    {/if}
                    {#if creds.password === PasswordState.MultipleSet}
                        Reset password
                    {/if}
                </Button>
            </div>
        </div>

        {#if creds.publicKeys.length === 0 && Object.values(creds.credentialPolicy).some(l => l?.includes(CredentialKind.Password))}
            <Alert color="warning">
                Your credential policy requires using a password for
                authentication. Without one, you won't be able to log in.
            </Alert>
        {/if}

        <div class="d-flex align-items-center mt-4 mb-2">
            <h4 class="m-0">One-time passwords</h4>
            <span class="ms-auto"></span>
            <Button
                color="link"
                onclick={e => {
            creatingOtpCredential = true
            e.preventDefault()
        }}
            >
                Add device
            </Button>
        </div>

        <div class="list-group list-group-flush mb-3">
            {#each creds.otp as credential (credential.id)}
                <div class="list-group-item credential">
                    <Fa fw icon={faMobilePhone} />
                    <span class="label ms-3">OTP device</span>
                    <span class="ms-auto"></span>
                    <Button
                        class="ms-2"
                        color="link"
                        onclick={e => {
                    deleteOtp(credential)
                    e.preventDefault()
                }}
                    >
                        Delete
                    </Button>
                </div>
            {/each}
        </div>

        {#if creds.otp.length === 0 && Object.values(creds.credentialPolicy).some(l => l?.includes(CredentialKind.Totp))}
            <Alert color="warning">
                Your credential policy requires using a one-time password for
                authentication. Without one, you won't be able to log in.
            </Alert>
        {/if}

        <div class="d-flex align-items-center mt-4 mb-2">
            <h4 class="m-0">Public keys</h4>
            <span class="ms-auto"></span>
            <Button
                color="link"
                id="addPublicKeyCredentialButton"
                title={creds.ldapLinked ? 'SSH keys are managed by LDAP' : ''}
                onclick={e => {
                if (creds?.ldapLinked) {
                    return
                }
                creatingPublicKeyCredential = true
                e.preventDefault()
            }}
            >
                Add key
            </Button>
            <Tooltip
                delay="250"
                target="addPublicKeyCredentialButton"
                animation
            >
                Public key credentials will be loaded from LDAP
            </Tooltip>
        </div>

        <div class="list-group list-group-flush mb-3">
            {#each creds.publicKeys as credential (credential.id)}
                <div class="list-group-item credential">
                    <Fa fw icon={faKey} />
                    <div class="main ms-3">
                        <div class="label">{credential.label}</div>
                        <small class="d-block text-muted"
                            >{credential.abbreviated}</small
                        >
                    </div>
                    <span class="ms-auto"></span>
                    <CredentialUsedStateBadge {credential} />
                    <Button
                        class="ms-2"
                        color="link"
                        disabled={creds.ldapLinked}
                        title={creds.ldapLinked ? 'SSH keys are managed by LDAP' : ''}
                        onclick={e => {
                    deletePublicKey(credential)
                    e.preventDefault()
                }}
                    >
                        Delete
                    </Button>
                </div>
            {/each}
        </div>

        {#if creds.publicKeys.length === 0 && creds.credentialPolicy.ssh?.includes(CredentialKind.PublicKey)}
            <Alert color="warning">
                Your credential policy requires using a public key for
                authentication. Without one, you won't be able to log in.
            </Alert>
        {/if}

        <div class="d-flex align-items-center mt-4 mb-2">
            <h4 class="m-0">Certificates</h4>
            <span class="ms-auto"></span>
            <Button
                color="link"
                onclick={e => {
            issuingCertificateCredential = true
            e.preventDefault()
        }}
            >
                Issue certificate
            </Button>
        </div>

        <div class="list-group list-group-flush mb-3">
            {#each creds.certificates as credential (credential.id)}
                <div class="list-group-item credential">
                    <Fa fw icon={faCertificate} />
                    <div class="main ms-3 abbreviate">
                        <div class="label">{credential.label}</div>
                        <small class="d-block text-muted abbreviate"
                            >SHA-256:
                            <code>{credential.fingerprint}</code></small
                        >
                    </div>
                    <span class="ms-auto"></span>
                    <CredentialUsedStateBadge {credential} />
                    <Button
                        color="link"
                        class="ms-2"
                        onclick={e => {
                    deleteCertificate(credential)
                    e.preventDefault()
                }}
                    >
                        Delete
                    </Button>
                </div>
            {/each}
        </div>

        {#if creds.certificates.length === 0 && creds.credentialPolicy.kubernetes?.includes(CredentialKind.Certificate)}
            <Alert color="warning">
                Your credential policy requires using a certificate for
                authentication. Without one, you won't be able to log in.
            </Alert>
        {/if}

        <div class="d-flex align-items-center mt-4 mb-2">
            <h4 class="m-0">Passkeys</h4>
            <span class="ms-auto"></span>
            <Button
                color="link"
                disabled={registeringWebauthn}
                onclick={e => {
                creatingWebauthn = true
                e.preventDefault()
            }}
            >
                Add passkey
            </Button>
        </div>

        {#if webauthnError}
            <Alert color="danger">{webauthnError}</Alert>
        {/if}

        <div class="list-group list-group-flush mb-3">
            {#each creds.webauthn as credential (credential.id)}
                <div class="list-group-item credential">
                    <Fa fw icon={faFingerprint} />
                    <div class="main ms-3">
                        <div class="label">{credential.label}</div>
                        {#if credential.dateAdded}
                            <small class="d-block text-muted">
                                Added
                                {new Date(credential.dateAdded).toLocaleDateString()}
                                {#if credential.lastUsed}
                                    · Last used
                                    {new Date(credential.lastUsed).toLocaleDateString()}
                                {/if}
                            </small>
                        {/if}
                    </div>
                    <span class="ms-auto"></span>
                    <Button
                        class="ms-2"
                        color="link"
                        onclick={e => {
                    deleteWebauthn(credential)
                    e.preventDefault()
                }}
                    >
                        Delete
                    </Button>
                </div>
            {/each}
        </div>

        {#if creds.webauthn.length === 0 && Object.values(creds.credentialPolicy).some(l => l?.includes(CredentialKind.WebAuthn))}
            <Alert color="warning">
                Your credential policy requires using a passkey for
                authentication. Without one, you won't be able to log in.
            </Alert>
        {/if}

        {#if creds.sso.length > 0}
            <div class="d-flex align-items-center mt-4 mb-2">
                <h4 class="m-0">Single sign-on</h4>
            </div>

            <div class="list-group list-group-flush mb-3">
                {#each creds.sso as credential (credential.id)}
                    <div class="list-group-item credential">
                        <Fa fw icon={faIdBadge} />
                        <span class="label ms-3">
                            {credential.email}
                            {#if credential.provider}
                                ({credential.provider})
                            {/if}
                        </span>
                    </div>
                {/each}
            </div>
        {/if}
    {/if}
</Loadable>

{#if changingPassword}
    <CreatePasswordModal
        bind:isOpen={changingPassword}
        create={changePassword}
    />
{/if}

{#if creatingPublicKeyCredential}
    <PublicKeyCredentialModal
        bind:isOpen={creatingPublicKeyCredential}
        save={createPublicKey}
    />
{/if}

{#if creatingOtpCredential && $serverInfo?.username}
    <CreateOtpModal
        bind:isOpen={creatingOtpCredential}
        username={$serverInfo.username}
        create={createOtp}
    />
{/if}

{#if issuingCertificateCredential && $serverInfo?.username}
    <CertificateCredentialModal
        bind:isOpen={issuingCertificateCredential}
        save={issueCertificate}
        username={$serverInfo.username}
        onClose={() => {
        issuingCertificateCredential = false
    }}
    />
{/if}

{#if creatingWebauthn}
    <WebauthnCredentialModal
        bind:isOpen={creatingWebauthn}
        userId=""
        save={registerWebauthn}
    />
{/if}

<style lang="scss">
    .credential {
        display: flex;
        align-items: center;
        padding-left: 0;
        padding-right: 0;
    }
</style>
