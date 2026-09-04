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
    import { TargetKind } from 'gateway/lib/api'
    import { serverInfo } from 'gateway/lib/store'
    import { untrack } from 'svelte'
    import Fa from 'svelte-fa'
    import TargetSshHostKeyChecker from './KeyChecker.svelte'

    interface Props {
        id: string
        options: TargetOptionsTargetSSHOptions
    }

    let { id, options }: Props = $props()

    let hostKeyCheckInvalidated = $state(false)
    let sshTargets = $state<Target[]>([])
    let clientKeys = $state<SSHClientKey[]>([])

    api.getSshOwnKeys().then(keys => {
        clientKeys = keys
    })

    $effect(() => {
        options // run effect when options get reassigned after saving
        hostKeyCheckInvalidated = false
    })

    function addCriticalOption() {
        if (options.auth.kind !== 'Certificate') {
            return
        }
        options.auth.allowedCriticalOptions = [
            ...(options.auth.allowedCriticalOptions ?? []),
            { name: '', value: undefined },
        ]
    }

    function removeCriticalOption(index: number) {
        if (options.auth.kind !== 'Certificate') {
            return
        }
        options.auth.allowedCriticalOptions = (
            options.auth.allowedCriticalOptions ?? []
        ).filter((_, i) => i !== index)
    }

    function addExtension() {
        if (options.auth.kind !== 'Certificate') {
            return
        }
        options.auth.allowedExtensions = [
            ...(options.auth.allowedExtensions ?? []),
            '',
        ]
    }

    function useDefaultExtensions() {
        if (options.auth.kind !== 'Certificate') {
            return
        }
        // Back to the absent key, which the server fills with `permit-pty`.
        // Not the same as the empty list, and reachable no other way: removing
        // rows can only ever arrive at `[]`, so without this an operator who
        // cleared the list could not undo it from the form.
        options.auth.allowedExtensions = undefined
    }

    function removeExtension(index: number) {
        if (options.auth.kind !== 'Certificate') {
            return
        }
        // `.filter` always yields an array, so removing the last entry leaves
        // an empty list rather than `undefined`. That distinction is load
        // bearing: an absent key lets the server apply its `permit-pty`
        // default, while an empty list means no extension is permitted at all,
        // and an operator who clears the list means the latter.
        options.auth.allowedExtensions = (
            options.auth.allowedExtensions ?? []
        ).filter((_, i) => i !== index)
    }

    api.getTargets().then(targets => {
        sshTargets = targets.filter(
            t => t.options.kind === TargetKind.Ssh && t.id !== id,
        )
    })

    // svelte-ignore state_referenced_locally
    let jumpHostSelectValue = $state(options.jumpHost ?? '')

    $effect(() => {
        const val = jumpHostSelectValue
        untrack(() => {
            options.jumpHost = val || undefined
        })
    })

    // Re-sync from options when the prop is reassigned (e.g. after save)
    $effect(() => {
        const jumpHost = options.jumpHost
        untrack(() => {
            jumpHostSelectValue = jumpHost ?? ''
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
            {#if $serverInfo?.hasVault}
                <option value="Certificate">Certificate issued by Vault</option>
            {/if}
            {#if $serverInfo?.runningOnEc2}
                <option value="IamRole">IAM Role (experimental)</option>
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
    {#if options.auth.kind === 'Certificate'}
        <FormGroup floating label="Vault signing role" class="w-100 ms-3">
            <input
                class="form-control"
                placeholder="Use the configured default role"
                value={options.auth.role ?? ''}
                oninput={e => {
                    // Emptied means "use the default", which is what the
                    // placeholder promises. Binding directly writes back `""`,
                    // and an empty role is not the default — `validate_segment`
                    // rejects it, so every session to this target then fails
                    // with "Invalid Vault role or mount configuration", which
                    // names nothing the operator can act on.
                    //
                    // The same bug as the critical-option value field below,
                    // thirty lines away, fixed in the commit that did not look
                    // for its siblings.
                    const typed = (e.currentTarget as HTMLInputElement).value
                    if (options.auth.kind === 'Certificate') {
                        options.auth.role = typed === '' ? undefined : typed
                    }
                }}
            >
        </FormGroup>
    {/if}
    {#if options.auth.kind === 'Password'}
        <FormGroup floating label="Password" class="w-100 ms-3">
            <input
                class="form-control"
                type="password"
                autocomplete="off"
                bind:value={options.auth.password}
            >
        </FormGroup>
    {/if}
</div>

{#if options.auth.kind === 'Certificate'}
    <div class="mb-3">
        <div class="d-flex align-items-center mb-2">
            <span class="me-auto">Allowed certificate critical options</span>
            <button
                type="button"
                class="btn btn-link btn-sm"
                onclick={addCriticalOption}
            >
                Add
            </button>
        </div>
        <small class="text-muted d-block mb-2">
            A certificate carrying any option not listed here is refused. The
            target's sshd enforces whatever arrives, so a
            <code>force-command</code>
            decides what the session runs — pin its value wherever you can.
            <strong>Pinning a value also makes the option mandatory:</strong>
            a certificate that leaves it out is refused too, so removing the
            option is not a way around the pin. Leave the value empty to permit
            the option without requiring it.
        </small>
        {#each options.auth.allowedCriticalOptions ?? [] as option, index}
            <div class="d-flex mb-2">
                <!--
                    Required, because a blank name is not "no restriction": it
                    pins the option named "", which no certificate carries, so
                    every connection to this target is then refused with a
                    message naming an empty string. Fails closed, but sends the
                    operator looking for a bug instead of at their own
                    half-filled row.
                -->
                <input
                    class="form-control me-2"
                    placeholder="force-command"
                    required
                    bind:value={option.name}
                >
                <input
                    class="form-control me-2"
                    placeholder="Any value"
                    value={option.value ?? ''}
                    oninput={e => {
                        // An emptied field means "any value", which is what the
                        // placeholder promises. Binding directly writes back ""
                        // instead, pinning the value to the empty string — it
                        // fails closed, but it does the opposite of what the
                        // operator was told.
                        const typed = e.currentTarget.value
                        option.value = typed === '' ? undefined : typed
                    }}
                >
                <button
                    type="button"
                    class="btn btn-link btn-sm"
                    onclick={() => removeCriticalOption(index)}
                >
                    Remove
                </button>
            </div>
        {/each}
    </div>
{/if}

{#if options.auth.kind === 'Certificate'}
    <div class="mb-3">
        <div class="d-flex align-items-center mb-2">
            <span class="me-auto">Allowed certificate extensions</span>
            {#if options.auth.allowedExtensions !== undefined}
                <button
                    type="button"
                    class="btn btn-link btn-sm"
                    onclick={useDefaultExtensions}
                >
                    Use the default
                </button>
            {/if}
            <button
                type="button"
                class="btn btn-link btn-sm"
                onclick={addExtension}
            >
                Add
            </button>
        </div>
        <small class="text-muted d-block mb-2">
            An allow-list: a certificate carrying any extension not listed here
            is refused, whatever the Vault role granted. Defaults to
            <code>permit-pty</code>
            alone, which is enough for an interactive session and nothing more.
            <strong
                >Reaching this target as a jump host needs
                <code>permit-port-forwarding</code>
                in both places</strong
            >
            — here, and in the Vault role's <code>default_extensions</code>.
            Either one without the other fails every session to this target
            rather than granting anything. An empty list is valid and means no
            extension is permitted at all.
        </small>
        {#if options.auth.allowedExtensions?.length === 0}
            <div class="text-warning small mb-2">
                Nothing is permitted: a certificate carrying any extension is
                refused, and one carrying none opens no interactive session.
            </div>
        {/if}
        {#each options.auth.allowedExtensions ?? [] as extension, index}
            <div class="d-flex mb-2">
                <input
                    class="form-control me-2"
                    placeholder="permit-port-forwarding"
                    required
                    value={extension}
                    oninput={e => {
                        // Written back through a fresh array rather than bound
                        // to the loop variable: the entries are strings, so
                        // there is no object to mutate by reference, and the
                        // `?? []` in the each expression means a binding has no
                        // guaranteed path back to the field.
                        if (options.auth.kind !== 'Certificate') {
                            return
                        }
                        const list = [...(options.auth.allowedExtensions ?? [])]
                        list[index] = e.currentTarget.value
                        options.auth.allowedExtensions = list
                    }}
                >
                <button
                    type="button"
                    class="btn btn-link btn-sm"
                    onclick={() => removeExtension(index)}
                >
                    Remove
                </button>
            </div>
        {/each}
    </div>
{/if}

<div class="d-flex">
    <Input
        class="mb-0 me-2"
        type="switch"
        label="Allow insecure SSH algorithms (e.g. for older network devices)"
        bind:checked={options.allowInsecureAlgos}
    />
</div>
