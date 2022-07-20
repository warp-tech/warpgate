<script type="ts">
    import { Alert, FormGroup } from 'sveltestrap'
    import { TargetKind } from 'gateway/lib/api'
    import { serverInfo } from 'gateway/lib/store'
    import { makeExampleSSHCommand, makeSSHUsername } from 'common/ssh'
    import { makeExampleMySQLCommand, makeExampleMySQLURI, makeMySQLUsername } from 'common/mysql'
    import CopyButton from 'common/CopyButton.svelte'
    import { makeTargetURL } from 'common/http'

    export let targetName: string|undefined
    export let targetKind: TargetKind
    export let username: string|undefined

    $: sshUsername = makeSSHUsername(targetName, username)
    $: exampleSSHCommand = makeExampleSSHCommand(targetName, username, $serverInfo)
    $: mySQLUsername = makeMySQLUsername(targetName, username)
    $: exampleMySQLCommand = makeExampleMySQLCommand(targetName, username, $serverInfo)
    $: exampleMySQLURI = makeExampleMySQLURI(targetName, username, $serverInfo)
    $: targetURL = targetName ? makeTargetURL(targetName) : ''
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
