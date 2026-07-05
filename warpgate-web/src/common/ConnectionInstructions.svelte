<script lang="ts">
    import { Button, FormGroup, ListGroup, ListGroupItem, Alert, Badge, Tooltip } from '@sveltestrap/sveltestrap'
    import { api, TargetKind, type ExistingCertificateCredential, type SsoKubernetesConfigDescription } from 'gateway/lib/api'
    import { serverInfo } from 'gateway/lib/store'
    import { makeExampleSSHCommand, makeCommonSelectorUsername, makeExampleMySQLCommand, makeExampleMySQLURI, makeMySQLUsername, makeTargetURL, makeExamplePostgreSQLCommand, makePostgreSQLUsername, makeExamplePostgreSQLURI, makeKubeconfig, makeExampleKubectlCommand, makeExampleSCPCommand, protocolHost, protocolPortString, makeOidcKubeconfig } from 'common/protocols'
    import { getCertificateKey, getAllCertificateKeys } from 'gateway/lib/certificateStore'
    import CertificateCredentialModal from 'admin/CertificateCredentialModal.svelte'
    import CopyableTextArea from 'common/CopyableTextArea.svelte'
    import DelayedSpinner from './DelayedSpinner.svelte'
    import InfoBox from './InfoBox.svelte'
    import { faCertificate, faPlus } from '@fortawesome/free-solid-svg-icons'
    import Fa from 'svelte-fa'

    interface Props {
        targetName?: string;
        targetKind: TargetKind;
        targetExternalHost?: string;
        username?: string;
        ticketSecret?: string;
        targetDefaultDatabaseName?: string;
    }

    let {
        targetName,
        targetKind,
        targetExternalHost = undefined,
        username,
        ticketSecret = undefined,
        targetDefaultDatabaseName = undefined,
    }: Props = $props()

    let clientCertificatePem: string | undefined = $state()
    let clientPrivateKeyPem: string | undefined = $state()
    let certLoading = $state(false)
    let certificates: CertificateWithKeyStatus[] = $state([])
    let selectedCertId: string = $state('')
    let issuingCertificate = $state(false)
    let pendingSelectCertId: string | undefined = $state()

    let k8sOidcConfigs: SsoKubernetesConfigDescription[] = $state([])
    let selectedOidcProvider: string | undefined = $state()
    let kubeconfigMode: 'oidc' | 'certificate' = $state('certificate')

    interface CertificateWithKeyStatus {
        credential: ExistingCertificateCredential
        hasLocalKey: boolean
    }

    async function loadCertificates () {
        certLoading = true
        try {
            const creds = await api.getMyCredentials()
            const localKeys = await getAllCertificateKeys()
            const localKeySet = new Set(localKeys.map(k => k.credentialId))

            certificates = creds.certificates.map(cert => ({
                credential: cert,
                hasLocalKey: localKeySet.has(cert.id),
            }))

            // If a cert was just issued, select it; otherwise pick the first with a local key
            const preferredId = pendingSelectCertId
            pendingSelectCertId = undefined
            const preferred = preferredId ? certificates.find(c => c.credential.id === preferredId) : undefined
            const toSelect = preferred ?? certificates.find(c => c.hasLocalKey) ?? certificates[0]
            if (toSelect) {
                selectedCertId = toSelect.credential.id
                await selectCertificate(toSelect.credential.id)
            }
        } catch {
            certificates = []
        } finally {
            certLoading = false
        }
    }

    async function loadOidcConfigs () {
        kubeconfigMode = 'certificate'
        k8sOidcConfigs = []
        selectedOidcProvider = undefined
        try {
            k8sOidcConfigs = await api.getSsoKubernetesConfigs()
        } catch {
            k8sOidcConfigs = []
        }
        const first = k8sOidcConfigs[0]
        if (first) {
            selectedOidcProvider = first.name
            kubeconfigMode = 'oidc'
        }
    }

    async function selectCertificate (credentialId: string) {
        selectedCertId = credentialId
        const result = await getLocalCertificate(credentialId)
        if (result) {
            clientCertificatePem = result.certificatePem
            clientPrivateKeyPem = result.privateKeyPem
        } else {
            clientCertificatePem = undefined
            clientPrivateKeyPem = undefined
        }
    }

    async function getLocalCertificate (credentialId: string): Promise<{
        certificatePem: string
        privateKeyPem: string
    } | null> {
        const local = await getCertificateKey(credentialId)
        if (!local) {
            return null
        }
        return {
            certificatePem: local.certificatePem,
            privateKeyPem: local.privateKeyPem,
        }
    }

    async function issueCertificate (label: string, publicKeyPem: string) {
        const response = await api.issueMyCertificate({
            issueCertificateCredentialRequest: {
                label,
                publicKeyPem,
            },
        })
        // Don't check IndexedDB here — the modal saves AFTER this callback returns.
        // We reload the full list (with correct key status) when the modal closes.
        pendingSelectCertId = response.credential.id
        return response
    }

    $effect(() => {
        if (targetKind === TargetKind.Kubernetes && !ticketSecret) {
            loadCertificates()
            loadOidcConfigs()
        }
    })

    let selectedOidc = $derived(k8sOidcConfigs.find(c => c.name === selectedOidcProvider))

    // Create a reactive opts object that updates when any prop or serverInfo changes
    let opts = $derived.by(() => ({
        targetName,
        username,
        serverInfo: $serverInfo,
        ticketSecret,
        targetExternalHost,
        targetDefaultDatabaseName,
        clientCertificatePem,
        clientPrivateKeyPem,
        oidcIssuerUrl: selectedOidc?.issuerUrl,
        oidcClientId: selectedOidc?.clientId,
        oidcScopes: selectedOidc?.scopes,
        oidcClientSecret: selectedOidc?.clientSecret ?? undefined,
    }))

    let commonSelectorUsername = $derived(makeCommonSelectorUsername(opts))
    let authHeader = $derived(`Authorization: Warpgate ${ticketSecret}`)
    let kubeconfig = $derived(makeKubeconfig(opts))
    let oidcKubeconfig = $derived(makeOidcKubeconfig(opts))
    let exampleKubectlCommand = $derived(makeExampleKubectlCommand(opts))

    function protocolEndpoint(protocol: 'ssh' | 'mysql' | 'postgres' | 'rdp' | 'vnc') {
        return `${protocolHost(opts, protocol)}:${protocolPortString(opts, protocol)}`
    }
</script>

{#if targetKind === TargetKind.Ssh}
    <CopyableTextArea label="SSH endpoint" value={protocolEndpoint('ssh')} />
    <CopyableTextArea label="SSH username" value={commonSelectorUsername} />
    <CopyableTextArea label="Example SSH command" value={makeExampleSSHCommand(opts)} />
    <CopyableTextArea label="Example SCP command" value={makeExampleSCPCommand(opts)} />
{/if}

{#if targetKind === TargetKind.Http}
    <CopyableTextArea label="Access URL" value={targetName ? makeTargetURL(opts) : ''} />

    {#if ticketSecret}
        Alternatively, set the <code>Authorization</code> header when accessing the URL:
        <CopyableTextArea label="Authorization header" value={authHeader} />
    {/if}
{/if}

{#if targetKind === TargetKind.MySql}
    <CopyableTextArea label="MySQL endpoint" value={protocolEndpoint('mysql')} />
    <CopyableTextArea label="MySQL username" value={makeMySQLUsername(opts)} />
    <CopyableTextArea label="Example MySQL command" value={makeExampleMySQLCommand(opts)} />
    <CopyableTextArea label="Example database URL" value={makeExampleMySQLURI(opts)} />

    <Alert color="info">
        Make sure you've set your client to require TLS and allowed cleartext password authentication.
    </Alert>
{/if}

{#if targetKind === TargetKind.Postgres}
    <CopyableTextArea label="PostgreSQL endpoint" value={protocolEndpoint('postgres')} />
    <CopyableTextArea label="PostgreSQL username" value={makePostgreSQLUsername(opts)} />
    <CopyableTextArea label="Example PostgreSQL command" value={makeExamplePostgreSQLCommand(opts)} />
    <CopyableTextArea label="Example database URL" value={makeExamplePostgreSQLURI(opts)} />

    <Alert color="info">
        Make sure you've set your client to require TLS and allowed cleartext password authentication.
    </Alert>
{/if}

{#if targetKind === TargetKind.Kubernetes}
    {#if k8sOidcConfigs.length > 0}
        <ul class="nav nav-pills mb-3">
            <li class="nav-item"><button class="nav-link {kubeconfigMode === 'oidc' ? 'active' : ''}" onclick={() => kubeconfigMode = 'oidc'}>OIDC with kubelogin</button></li>
            <li class="nav-item"><button class="nav-link {kubeconfigMode === 'certificate' ? 'active' : ''}" onclick={() => kubeconfigMode = 'certificate'}>Certificate authentication</button></li>
        </ul>
    {/if}

    {#if kubeconfigMode === 'oidc' && k8sOidcConfigs.length > 0}
        {#if k8sOidcConfigs.length > 1}
            <label class="form-label" for="oidc-provider-select">SSO provider</label>
            <select id="oidc-provider-select" class="form-select mb-3" bind:value={selectedOidcProvider}>
                {#each k8sOidcConfigs as c (c.name)}
                    <option value={c.name}>{c.label}</option>
                {/each}
            </select>
        {/if}
        <CopyableTextArea label="Kubeconfig file" value={oidcKubeconfig} />
        <div class="text-muted small mb-3">Requires the <a href="https://github.com/int128/kubelogin" target="_blank" rel="noreferrer noopener">kubelogin</a> (oidc-login) kubectl plugin.</div>
    {/if}

    {#if kubeconfigMode === 'certificate' || k8sOidcConfigs.length === 0}
    <div class="row">
        <div class="col-12 col-lg">
            <!-- svelte-ignore a11y_label_has_associated_control -->
            {#if !ticketSecret}
                {#if certificates.length > 0}
                    <label class="form-label">Choose a certificate</label>
                {/if}
                {#if certLoading}
                    <DelayedSpinner />
                {:else}
                    <ListGroup flush class="mb-2">
                        {#each certificates as cert (cert.credential.id)}
                            <ListGroupItem tag="a" href="#" action class="list-group-item list-group-item-action d-flex align-items-center gap-3"
                                active={cert.credential.id === selectedCertId}
                                onclick={e => {
                                    e.preventDefault()
                                    selectCertificate(cert.credential.id)
                                }}
                                >
                                <Fa fw icon={faCertificate} />
                                <div class="me-auto">{cert.credential.label}</div>
                                {#if cert.hasLocalKey}
                                    <Badge
                                        id="cert-status-badge-{cert.credential.id}"
                                        color="success"
                                    >Key available</Badge>
                                {:else}
                                    <Badge
                                    id="cert-status-badge-{cert.credential.id}"
                                        color="warning"
                                    >No private key</Badge>
                                {/if}
                                <Tooltip target={'cert-status-badge-' + cert.credential.id} placement="top" delay={500}>
                                    {#if cert.hasLocalKey}
                                        This certificate's private key is stored locally in this browser and can be used to generate a kubeconfig with working credentials.
                                    {:else}
                                        This certificate's private key is not stored locally in this browser. You can still generate a kubeconfig, but it will contain placeholders for authentication and won't work until you fill in the actual certificate and key data.
                                    {/if}
                                </Tooltip>
                            </ListGroupItem>
                        {/each}
                    </ListGroup>

                    {#if $serverInfo?.ownCredentialManagementAllowed}
                    <Button
                        color={certificates.length > 0 ? 'secondary' : 'primary'}
                        class="d-flex w-100 text-center justify-content-center align-items-center gap-2 my-3"
                        onclick={() => {
                            issuingCertificate = true
                        }}
                        >
                        <Fa fw icon={faPlus} />
                        <div>
                            {#if certificates.length > 0}
                                Issue a new certificate
                            {:else}
                                Issue a certificate
                            {/if}
                        </div>
                    </Button>
                    {/if}

                    {#if !selectedCertId || !clientPrivateKeyPem}
                        <InfoBox class="mb-2">
                            {#if certificates.length > 0}
                                {#if !selectedCertId}
                                    There is no certificate selected.
                                {:else}
                                    The private key for this certificate is not stored in this browser.
                                {/if}
                                The kubeconfig will contain placeholders for authentication.
                            {:else}
                                You need a certificate credential to connect to this target.
                            {/if}
                        </InfoBox>
                        <InfoBox>
                            You can issue a new certificate using the button above and enable the "Store in browser" option to generate a ready-to-use kubeconfig.
                        </InfoBox>
                    {/if}
                {/if}
            {/if}
        </div>
        {#if certificates.length > 0}
        <div class="col-12 col-lg">
            <CopyableTextArea label="Kubeconfig file" value={kubeconfig} />
            <CopyableTextArea label="Example kubectl command" value={exampleKubectlCommand} />

            <InfoBox class="mt-3">
                Save the kubeconfig above to a file (e.g. <code>warpgate-kubeconfig.yaml</code>) and use it with kubectl.
            </InfoBox>
        </div>
        {/if}
    </div>
    {/if}
{/if}

{#if issuingCertificate}
    <CertificateCredentialModal
        bind:isOpen={issuingCertificate}
        save={issueCertificate}
        username={username ?? ''}
        storeInBrowserByDefault={true}
        onClose={() => { issuingCertificate = false; loadCertificates() }}
    />
{/if}

{#if targetKind === TargetKind.Rdp}
    <CopyableTextArea label="RDP endpoint" value={protocolEndpoint('rdp')} />
    <CopyableTextArea label="RDP username" value={commonSelectorUsername} />
{/if}

{#if targetKind === TargetKind.Vnc}
    <CopyableTextArea label="VNC endpoint" value={protocolEndpoint('vnc')} />
    <CopyableTextArea label="VNC username" value={commonSelectorUsername} />
{/if}
