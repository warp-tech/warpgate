<script lang="ts">
    import { FormGroup, Input } from '@sveltestrap/sveltestrap'
    import { api, type Target, type TargetOptionsTargetSSHOptions } from '../../../lib/api'
    import { faExternalLink } from '@fortawesome/free-solid-svg-icons'
    import Fa from 'svelte-fa'
    import TargetSshHostKeyChecker from './KeyChecker.svelte'
    import Alert from 'common/sveltestrap-s5-ports/Alert.svelte'
    import { adminPermissions } from 'admin/lib/store'
    import { serverInfo } from 'gateway/lib/store'
    import { TargetKind } from 'gateway/lib/api'
    import { untrack } from 'svelte'

    interface Props {
        id: string,
        options: TargetOptionsTargetSSHOptions,
    }

    let { id, options }: Props = $props()

    let hostKeyCheckInvalidated = $state(false)
    let sshTargets = $state<Target[]>([])

    $effect(() => {
        // eslint-disable-next-line @typescript-eslint/no-unused-expressions
        options // run effect when options get reassigned after saving
        hostKeyCheckInvalidated = false
    })

    api.getTargets().then(targets => {
        sshTargets = targets.filter(t => t.options.kind === TargetKind.Ssh && t.id !== id)
    })

    // svelte-ignore state_referenced_locally
    let jumpHostSelectValue = $state(options.jumpHost ?? '')

    $effect(() => {
        const val = jumpHostSelectValue
        untrack(() => { options.jumpHost = val || undefined })
    })

    // Re-sync from options when the prop is reassigned (e.g. after save)
    $effect(() => {
        const jumpHost = options.jumpHost
        untrack(() => { jumpHostSelectValue = jumpHost ?? '' })
    })
</script>

<h4 class="mt-4">Connection</h4>

<div class="row">
    {#if sshTargets.length}
        <div class="col">
            <FormGroup floating label="Jump host">
                <select class="form-control" bind:value={jumpHostSelectValue}>
                    <option value="">Direct connection</option>
                    {#each sshTargets as target (target.id)}
                        <option value={target.id}>{target.name}</option>
                    {/each}
                </select>
            </FormGroup>
        </div>
    {/if}
    <div class="col" style="flex-grow: 2">
        <FormGroup floating label="Target host">
            <input class="form-control" bind:value={options.host} onchange={() => hostKeyCheckInvalidated = true} />
        </FormGroup>
    </div>
    <div class="col">
        <FormGroup floating label="Target port">
            <input class="form-control" type="number" bind:value={options.port} min="1" max="65535" step="1" onchange={() => hostKeyCheckInvalidated = true} />
        </FormGroup>
    </div>
</div>

{#if $adminPermissions.targetsEdit}
<div class="mb-3">
    {#if !hostKeyCheckInvalidated}
    <TargetSshHostKeyChecker id={id} options={options} />
    {:else}
    <Alert color="secondary">Save changes to see the host key validation status</Alert>
    {/if}
</div>
{/if}

<h4 class="mt-4">Authentication</h4>

<FormGroup floating label="Username">
    <input class="form-control"
        placeholder="Use the currently logged in user's name"
        bind:value={options.username}
    />
</FormGroup>

<div class="d-flex">
    <FormGroup floating label="Authenticate using" class="w-100">
        <select bind:value={options.auth.kind} class="form-control">
            <option value="PublicKey">Warpgate's own private keys</option>
            <option value="Password">Password</option>
            {#if $serverInfo?.runningOnEc2}
                <option value="IamRole">IAM Role (experimental)</option>
            {/if}
        </select>
    </FormGroup>
    {#if options.auth.kind === 'PublicKey'}
        <a
            class="btn btn-link mb-3 d-flex align-items-center"
            href="/@warpgate/admin#/config/ssh"
            target="_blank">
            <Fa fw icon={faExternalLink} />
        </a>
    {/if}
    {#if options.auth.kind === 'Password'}
        <FormGroup floating label="Password" class="w-100 ms-3">
            <input class="form-control" type="password" autocomplete="off" bind:value={options.auth.password} />
        </FormGroup>
    {/if}
</div>

<div class="d-flex">
    <Input
        class="mb-0 me-2"
        type="switch"
        label="Allow insecure SSH algorithms (e.g. for older network devices)"
        bind:checked={options.allowInsecureAlgos} />
</div>
