<script lang="ts">
    import { Button, FormGroup, ListGroup, ListGroupItem } from '@sveltestrap/sveltestrap'
    import { api, TargetKind, type ExistingCertificateCredential } from 'gateway/lib/api'
    import { serverInfo } from 'gateway/lib/store'
    import { makeExampleSSHCommand, makeSSHUsername, makeExampleMySQLCommand, makeExampleMySQLURI, makeMySQLUsername, makeTargetURL, makeExamplePostgreSQLCommand, makePostgreSQLUsername, makeExamplePostgreSQLURI, makeKubeconfig, makeExampleKubectlCommand, makeExampleSCPCommand } from 'common/protocols'
    import { getCertificateKey, getAllCertificateKeys } from 'gateway/lib/certificateStore'
    import CertificateCredentialModal from 'admin/CertificateCredentialModal.svelte'
    import CopyButton from 'common/CopyButton.svelte'
    import Alert from './sveltestrap-s5-ports/Alert.svelte'
    import DelayedSpinner from './DelayedSpinner.svelte'
    import InfoBox from './InfoBox.svelte'
    import { faCertificate, faPlus } from '@fortawesome/free-solid-svg-icons'
    import Fa from 'svelte-fa'
    import Badge from './sveltestrap-s5-ports/Badge.svelte'
    import Tooltip from './sveltestrap-s5-ports/Tooltip.svelte'

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
        }
    })

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
    }))

    let sshUsername = $derived(makeSSHUsername(opts))
    let exampleSSHCommand = $derived(makeExampleSSHCommand(opts))
    let exampleSCPCommand = $derived(makeExampleSCPCommand(opts))
    let mySQLUsername = $derived(makeMySQLUsername(opts))
    let exampleMySQLCommand = $derived(makeExampleMySQLCommand(opts))
    let exampleMySQLURI = $derived(makeExampleMySQLURI(opts))
    let postgreSQLUsername = $derived(makePostgreSQLUsername(opts))
    let examplePostgreSQLCommand = $derived(makeExamplePostgreSQLCommand(opts))
    let examplePostgreSQLURI = $derived(makeExamplePostgreSQLURI(opts))
    let targetURL = $derived(targetName ? makeTargetURL(opts) : '')
    let authHeader = $derived(`Authorization: Warpgate ${ticketSecret}`)
    let kubeconfig = $derived(makeKubeconfig(opts))
    let exampleKubectlCommand = $derived(makeExampleKubectlCommand(opts))
</script>

{#if targetKind === TargetKind.Ssh}
    <FormGroup floating label="SSH username" class="d-flex align-items-center">
        <input type="text" class="form-control" readonly value={sshUsername} />
        <CopyButton text={sshUsername} />
    </FormGroup>

    <FormGroup floating label="Example SSH command" class="d-flex align-items-center">
        <input type="text" class="form-control" readonly value={exampleSSHCommand} />
        <CopyButton text={exampleSSHCommand} />
    </FormGroup>

    <FormGroup floating label="Example SCP command" class="d-flex align-items-center">
        <input type="text" class="form-control" readonly value={exampleSCPCommand} />
        <CopyButton text={exampleSCPCommand} />
    </FormGroup>
{/if}

{#if targetKind === TargetKind.Http}
    <FormGroup floating label="Access URL" class="d-flex align-items-center">
        <input type="text" class="form-control" readonly value={targetURL} />
        <CopyButton text={targetURL} />
    </FormGroup>

    {#if ticketSecret}
        Alternatively, set the <code>Authorization</code> header when accessing the URL:
        <FormGroup floating label="Authorization header" class="d-flex align-items-center">
            <input type="text" class="form-control" readonly value={authHeader} />
            <CopyButton text={authHeader} />
        </FormGroup>
    {/if}
{/if}

{#if targetKind === TargetKind.MySql}
    <FormGroup floating label="MySQL username" class="d-flex align-items-center">
        <input type="text" class="form-control" readonly value={mySQLUsername} />
        <CopyButton text={mySQLUsername} />
    </FormGroup>

    <FormGroup floating label="Example command" class="d-flex align-items-center">
        <input type="text" class="form-control" readonly value={exampleMySQLCommand} />
        <CopyButton text={exampleMySQLCommand} />
    </FormGroup>

    <FormGroup floating label="Example database URL" class="d-flex align-items-center">
        <input type="text" class="form-control" readonly value={exampleMySQLURI} />
        <CopyButton text={exampleMySQLURI} />
    </FormGroup>

    <Alert color="info">
        Make sure you've set your client to require TLS and allowed cleartext password authentication.
    </Alert>
{/if}

{#if targetKind === TargetKind.Postgres}
<FormGroup floating label="PostgreSQL username" class="d-flex align-items-center">
    <input type="text" class="form-control" readonly value={postgreSQLUsername} />
    <CopyButton text={postgreSQLUsername} />
</FormGroup>

<FormGroup floating label="Example command" class="d-flex align-items-center">
    <input type="text" class="form-control" readonly value={examplePostgreSQLCommand} />
    <CopyButton text={examplePostgreSQLCommand} />
</FormGroup>

<FormGroup floating label="Example database URL" class="d-flex align-items-center">
    <input type="text" class="form-control" readonly value={examplePostgreSQLURI} />
    <CopyButton text={examplePostgreSQLURI} />
</FormGroup>

<Alert color="info">
    Make sure you've set your client to require TLS and allowed cleartext password authentication.
</Alert>
{/if}

{#if targetKind === TargetKind.Kubernetes}
<h4 class="mb-3">Connect with kubectl</h4>
<div class="row">
    <div class="col-12 col-lg-6">
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
    <div class="col-12 col-lg-6">
        <FormGroup floating label="Kubeconfig file" class="d-flex align-items-center">
            <textarea class="form-control" readonly style="height: 27rem; font-family: monospace; font-size: 0.9em;">{kubeconfig}</textarea>
            <CopyButton text={kubeconfig} />
        </FormGroup>

        <FormGroup floating label="Example kubectl command" class="d-flex align-items-center">
            <input type="text" class="form-control" readonly value={exampleKubectlCommand} />
            <CopyButton text={exampleKubectlCommand} />
        </FormGroup>

        <InfoBox class="mt-3">
            Save the kubeconfig above to a file (e.g. <code>warpgate-kubeconfig.yaml</code>) and use it with kubectl.
        </InfoBox>
    </div>
</div>
{/if}

{#if issuingCertificate}
<CertificateCredentialModal
    bind:isOpen={issuingCertificate}
    save={issueCertificate}
    username={username ?? ''}
    storeInBrowserByDefault={true}
    closeOnIssue={true}
    onClose={() => { issuingCertificate = false; loadCertificates() }}
/>
{/if}
