<script lang="ts">
    import {
        Alert,
        ButtonGroup,
        Dropdown,
        DropdownItem,
        DropdownMenu,
        DropdownToggle,
    } from '@sveltestrap/sveltestrap'
    import AsyncButton from 'common/AsyncButton.svelte'
    import { formatDurationAsHumantime } from 'common/duration'
    import Loadable from 'common/Loadable.svelte'
    import RelativeDate from 'common/RelativeDate.svelte'
    import {
        ApiAuthState,
        type AuthStateResponseInternal,
        api,
        WebApprovalScope,
    } from 'gateway/lib/api'

    interface Props {
        params: { stateId: string }
    }

    let { params }: Props = $props()

    let authState: AuthStateResponseInternal | undefined = $state()
    let webauthnBusy = $state(false)
    let webauthnError: string | null = $state(null)
    let webauthnRequired = $state(false)

    let cachingGrace = $derived(authState?.webApprovalCachingGraceSeconds ?? 0)
    let cachingEnabled = $derived(cachingGrace > 0)
    let graceLabel = $derived(formatDurationAsHumantime(cachingGrace))

    async function reload() {
        authState = await api.getAuthState({ id: params.stateId })
        // If the session state indicates WebAuthn is needed, the approval should
        // include a WebAuthn ceremony
        webauthnRequired = authState?.state === ApiAuthState.WebAuthnNeeded
    }

    async function init() {
        await reload()
    }

    async function approve(scope: WebApprovalScope) {
        // If WebAuthn is required for this session, perform the ceremony first
        if (webauthnRequired) {
            const success = await performWebauthnCeremony()
            if (!success) return
        }
        await api.approveAuth({
            id: params.stateId,
            approveAuthRequest: { scope },
        })
        await reload()
        window.close()
    }

    async function performWebauthnCeremony(): Promise<boolean> {
        webauthnBusy = true
        webauthnError = null
        try {
            const startResp = await api.startWebauthnAuthentication()
            const challengeOptions = JSON.parse(startResp.challengeJson)

            const credential = (await navigator.credentials.get({
                publicKey: {
                    ...challengeOptions.publicKey,
                    challenge: base64UrlToBuffer(
                        challengeOptions.publicKey.challenge,
                    ),
                    allowCredentials: (
                        challengeOptions.publicKey.allowCredentials ?? []
                    ).map((c: { id: string }) => ({
                        ...c,
                        id: base64UrlToBuffer(c.id),
                    })),
                },
            })) as PublicKeyCredential | null

            if (!credential) {
                webauthnError = 'Authentication was cancelled'
                return false
            }

            const response =
                credential.response as AuthenticatorAssertionResponse
            const credentialJson = JSON.stringify({
                id: credential.id,
                rawId: bufferToBase64Url(credential.rawId),
                type: credential.type,
                response: {
                    authenticatorData: bufferToBase64Url(
                        response.authenticatorData,
                    ),
                    clientDataJSON: bufferToBase64Url(response.clientDataJSON),
                    signature: bufferToBase64Url(response.signature),
                    userHandle: response.userHandle
                        ? bufferToBase64Url(response.userHandle)
                        : null,
                },
            })

            await api.completeWebauthnAuthentication({
                authenticationCompleteRequest: { credentialJson },
            })
            return true
        } catch (e: unknown) {
            webauthnError =
                e instanceof Error
                    ? e.message
                    : 'WebAuthn authentication failed'
            return false
        } finally {
            webauthnBusy = false
        }
    }

    async function reject() {
        await api.rejectAuth({ id: params.stateId })
        await reload()
        window.close()
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

<style lang="scss">
    .identification-string {
        display: flex;
        font-size: 3rem;

        .card {
            padding: 0rem 0.5rem;
            border-radius: .5rem;
            margin-right: .5rem;
        }
    }
</style>

<Loadable promise={init()}>
    {#if authState}
        <div class="page-summary-bar">
            <h1>authorization request</h1>
        </div>

        <div class="mb-5">
            <div class="mb-2">
                Ensure this security key matches your authentication prompt:
            </div>
            <div class="identification-string">
                {#each authState?.identificationString as char}
                    <div class="card bg-secondary text-light">
                        <div class="card-body">{char}</div>
                    </div>
                {/each}
            </div>
        </div>

        <div class="mb-3">
            <div>Authorize this {authState.protocol} session?</div>
            <small>
                Requested <RelativeDate date={authState.started} />
                {#if authState.address}
                    from {authState.address}
                {/if}
            </small>
        </div>

        {#if authState.state === ApiAuthState.Success}
            <Alert color="success"> Approved </Alert>
        {:else if authState.state === ApiAuthState.Failed}
            <Alert color="danger"> Rejected </Alert>
        {:else}
            {#if webauthnRequired}
                <div class="mb-3">
                    <Alert color="info">
                        This session requires security key verification. Touch
                        your key when prompted.
                    </Alert>
                </div>
            {/if}
            {#if webauthnError}
                <Alert color="danger">{webauthnError}</Alert>
            {/if}
            <div class="d-flex">
                <div class="ms-auto"></div>
                {#if cachingEnabled}
                    <ButtonGroup>
                        <AsyncButton
                            color="primary"
                            disabled={webauthnBusy}
                            click={() => approve(WebApprovalScope.Target)}
                        >
                            {webauthnRequired ? 'Verify & authorize' : 'Authorize & remember for'}
                            {cachingEnabled && !webauthnRequired ? graceLabel : ''}
                        </AsyncButton>
                        <Dropdown class="btn-group">
                            <DropdownToggle
                                color="primary"
                                caret
                                class="ps-2"
                            />
                            <DropdownMenu end>
                                <DropdownItem
                                    onclick={() => approve(WebApprovalScope.AllTargets)}
                                >
                                    {webauthnRequired ? 'Verify & authorize' : 'Authorize'}
                                    for all targets
                                    {cachingEnabled && !webauthnRequired ? `& remember for ${graceLabel}` : ''}
                                </DropdownItem>
                                <DropdownItem
                                    onclick={() => approve(WebApprovalScope.Once)}
                                >
                                    {webauthnRequired ? 'Verify & authorize' : 'Authorize'}
                                    this time only
                                </DropdownItem>
                            </DropdownMenu>
                        </Dropdown>
                    </ButtonGroup>
                {:else}
                    <AsyncButton
                        color="primary"
                        disabled={webauthnBusy}
                        click={() => approve(WebApprovalScope.Once)}
                    >
                        {webauthnRequired ? 'Verify & authorize' : 'Authorize'}
                    </AsyncButton>
                {/if}
                <AsyncButton
                    color="secondary"
                    class="d-flex align-items-center ms-2"
                    click={reject}
                >
                    Reject
                </AsyncButton>
            </div>
        {/if}
    {/if}
</Loadable>
