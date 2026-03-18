<script lang="ts">
    import { FormGroup } from '@sveltestrap/sveltestrap'
    import { TargetKind } from 'gateway/lib/api'
    import { serverInfo } from 'gateway/lib/store'
    import { makeExampleSSHCommand, makeSSHUsername, makeExampleMySQLCommand, makeExampleMySQLURI, makeMySQLUsername, makeTargetURL, makeExamplePostgreSQLCommand, makePostgreSQLUsername, makeExamplePostgreSQLURI, makeKubeconfig, makeExampleKubectlCommand, makeExampleSCPCommand } from 'common/protocols'
    import { ensureCertificateCredential } from 'gateway/lib/certificateProvisioner'
    import CopyButton from 'common/CopyButton.svelte'
    import Alert from './sveltestrap-s5-ports/Alert.svelte'

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
    let certError: string | undefined = $state()

    async function provisionCertificate () {
        certLoading = true
        certError = undefined
        try {
            const result = await ensureCertificateCredential()
            clientCertificatePem = result.certificatePem
            clientPrivateKeyPem = result.privateKeyPem
        } catch {
            certError = 'Could not auto-provision a certificate. You may need to issue one manually in your credential settings.'
        } finally {
            certLoading = false
        }
    }

    $effect(() => {
        if (targetKind === TargetKind.Kubernetes && !ticketSecret) {
            provisionCertificate()
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
{#if certLoading && !ticketSecret}
<Alert color="info">
    Provisioning certificate...
</Alert>
{:else if certError && !ticketSecret}
<Alert color="warning">
    {certError}
</Alert>
{/if}

<FormGroup floating label="Kubeconfig file" class="d-flex align-items-center">
    <textarea class="form-control" readonly style="height: 27rem; font-family: monospace; font-size: 0.9em;">{kubeconfig}</textarea>
    <CopyButton text={kubeconfig} />
</FormGroup>

<FormGroup floating label="Example kubectl command" class="d-flex align-items-center">
    <input type="text" class="form-control" readonly value={exampleKubectlCommand} />
    <CopyButton text={exampleKubectlCommand} />
</FormGroup>

<Alert color="info">
    Save the kubeconfig above to a file (e.g., <code>warpgate-kubeconfig.yaml</code>) and use it with kubectl.
</Alert>
{/if}
