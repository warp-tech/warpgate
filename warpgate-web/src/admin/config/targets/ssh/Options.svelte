<script lang="ts">
    import { faExternalLink } from '@fortawesome/free-solid-svg-icons'
    import { Alert, FormGroup, Input } from '@sveltestrap/sveltestrap'
    import {
        api,
        type SSHClientKey,
        type Target,
        type TargetOptionsTargetSSHOptions,
    } from 'admin/lib/api'
    import { adminPermissions } from 'admin/lib/store'
    import SearchSelect from 'common/SearchSelect.svelte'
    import SecretRefInput from 'common/SecretRefInput.svelte'
    import { TargetKind } from 'gateway/lib/api'
    import { serverInfo } from 'gateway/lib/store'
    import { untrack } from 'svelte'
    import Fa from 'svelte-fa'
    import TargetSshHostKeyChecker from './KeyChecker.svelte'

    interface Props {
        id: string
        name: string
        options: TargetOptionsTargetSSHOptions
    }

    let { id, name, options }: Props = $props()

    let hostKeyCheckInvalidated = $state(false)
    let hasOtherSshTargets = $state(false)
    let jumpHostTarget = $state<Target | undefined>()
    let clientKeys = $state<SSHClientKey[]>([])

    api.getSshOwnKeys().then(keys => {
        clientKeys = keys
    })

    $effect(() => {
        options // run effect when options get reassigned after saving
        hostKeyCheckInvalidated = false
    })

    // Other SSH targets are searched for as the user types rather than
    // loaded up front, as there may be very many of them.
    async function searchJumpHosts(search: string) {
        const page = await api.getTargetsPage({
            search,
            kind: TargetKind.Ssh,
            limit: 50,
        })
        const items = page.items.filter(t => t.id !== id)
        return { items, total: page.total - (page.items.length - items.length) }
    }

    searchJumpHosts('').then(page => {
        hasOtherSshTargets = page.items.length > 0
    })

    // Resolve the configured jump host's id to show its name, including when
    // the prop is reassigned (e.g. after save)
    $effect(() => {
        const jumpHost = options.jumpHost
        untrack(() => {
            if (!jumpHost) {
                jumpHostTarget = undefined
            } else if (jumpHostTarget?.id !== jumpHost) {
                api.getTarget({ id: jumpHost })
                    .then(target => {
                        if (options.jumpHost === target.id) {
                            jumpHostTarget = target
                        }
                    })
                    // A deleted jump host has no name to show
                    .catch(() => {})
            }
        })
    })

    // svelte-ignore state_referenced_locally
    let clientKeySelectValue = $state(
        options.auth.kind === 'PublicKey' ? (options.auth.keyId ?? '') : '',
    )

    $effect(() => {
        const val = clientKeySelectValue
        untrack(() => {
            if (options.auth.kind === 'PublicKey') {
                options.auth.keyId = val || undefined
            }
        })
    })

    $effect(() => {
        const keyId =
            options.auth.kind === 'PublicKey' ? options.auth.keyId : undefined
        untrack(() => {
            clientKeySelectValue = keyId ?? ''
        })
    })
</script>

<h4 class="mt-4">Connection</h4>

<div class="row">
    {#if hasOtherSshTargets || options.jumpHost}
        <div class="col">
            <FormGroup floating label="Jump host">
                <SearchSelect
                    bind:value={jumpHostTarget}
                    load={searchJumpHosts}
                    itemLabel={target => target.name}
                    itemKey={target => target.id}
                    emptyOption="Direct connection"
                    placeholder="Direct connection"
                    onchange={target => {
                        options.jumpHost = target?.id
                    }}
                />
            </FormGroup>
        </div>
    {/if}
    <div class="col" style="flex-grow: 2">
        <FormGroup floating label="Target host">
            <input
                class="form-control"
                bind:value={options.host}
                onchange={() => hostKeyCheckInvalidated = true}
            >
        </FormGroup>
    </div>
    <div class="col">
        <FormGroup floating label="Target port">
            <input
                class="form-control"
                type="number"
                bind:value={options.port}
                min="1"
                max="65535"
                step="1"
                onchange={() => hostKeyCheckInvalidated = true}
            >
        </FormGroup>
    </div>
</div>

{#if $adminPermissions.targetsEdit}
    <div class="mb-3">
        {#if !hostKeyCheckInvalidated}
            <TargetSshHostKeyChecker {id} {options} />
        {:else}
            <Alert color="secondary">
                Save changes to see the host key validation status
            </Alert>
        {/if}
    </div>
{/if}

<h4 class="mt-4">Authentication</h4>

<FormGroup floating label="Username">
    <input
        class="form-control"
        placeholder="Use the currently logged in user's name"
        bind:value={options.username}
    >
</FormGroup>

<div class="d-flex">
    <FormGroup floating label="Authenticate using" class="w-100">
        <select bind:value={options.auth.kind} class="form-control">
            <option value="PublicKey">Warpgate's own private keys</option>
            <option value="Password">Password</option>
            {#if $serverInfo?.runningOnEc2}
                <option value="IamRole">IAM Role</option>
            {/if}
        </select>
    </FormGroup>
    {#if options.auth.kind === 'PublicKey'}
        <FormGroup floating label="Key" class="w-100 ms-3">
            <select class="form-control" bind:value={clientKeySelectValue}>
                <option value="">Use default keys</option>
                {#each clientKeys as key (key.id)}
                    <option value={key.id}>
                        {key.label}
                        ({key.kind}){key.isDefault ? ' — default' : ''}
                    </option>
                {/each}
            </select>
        </FormGroup>
        <a
            class="btn btn-link mb-3 d-flex align-items-center"
            href="/@warpgate/admin#/config/ssh"
            target="_blank"
        >
            <Fa fw icon={faExternalLink} />
        </a>
    {/if}
    {#if options.auth.kind === 'Password'}
        <div class="w-100 ms-3 d-flex align-items-center">
            <SecretRefInput
                bind:value={options.auth.password}
                inlineLabel="Password"
                disabled={!$adminPermissions.targetsEdit}
                intendedUsage={{
                    kind: 'Target',
                    id,
                    name
                }}
            />
        </div>
    {/if}
</div>

<div class="d-flex">
    <Input
        class="mb-0 me-2"
        type="switch"
        label="Allow insecure SSH algorithms (e.g. for older network devices)"
        bind:checked={options.allowInsecureAlgos}
    />
</div>
