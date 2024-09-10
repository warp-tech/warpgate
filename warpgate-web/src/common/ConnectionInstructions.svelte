<script lang="ts">
    import { Alert, FormGroup } from '@sveltestrap/sveltestrap'
    import { TargetKind } from 'gateway/lib/api'
    import { serverInfo } from 'gateway/lib/store'
    import { makeExampleSSHCommand, makeSSHUsername, makeExampleMySQLCommand, makeExampleMySQLURI, makeMySQLUsername, makeTargetURL } from 'common/protocols'
    import CopyButton from 'common/CopyButton.svelte'

    export let targetName: string|undefined
    export let targetKind: TargetKind
    export let targetExternalHost: string|undefined = undefined
    export let username: string|undefined
    export let ticketSecret: string|undefined = undefined

    $: opts = {
        targetName,
        username,
        serverInfo: $serverInfo,
        ticketSecret,
        targetExternalHost,
    }
    $: sshUsername = makeSSHUsername(opts)
    $: exampleSSHCommand = makeExampleSSHCommand(opts)
    $: mySQLUsername = makeMySQLUsername(opts)
    $: exampleMySQLCommand = makeExampleMySQLCommand(opts)
    $: exampleMySQLURI = makeExampleMySQLURI(opts)
    $: targetURL = targetName ? makeTargetURL(opts) : ''
    $: authHeader = `Authorization: Warpgate ${ticketSecret}`
</script>

{#if targetKind === TargetKind.Ssh}
    <FormGroup floating label="SSH username" class="d-flex align-items-center">
        <input type="text" class="form-control" readonly value={sshUsername} />
        <CopyButton text={sshUsername} />
    </FormGroup>

    <FormGroup floating label="Example command" class="d-flex align-items-center">
        <input type="text" class="form-control" readonly value={exampleSSHCommand} />
        <CopyButton text={exampleSSHCommand} />
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
