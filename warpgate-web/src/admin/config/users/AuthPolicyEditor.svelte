<script lang="ts">
    import { Input } from '@sveltestrap/sveltestrap'
    import {
        CredentialKind,
        type UserRequireCredentialsPolicy,
    } from 'admin/lib/api'
    import InfoBox from 'common/InfoBox.svelte'
    import { SvelteSet } from 'svelte/reactivity'
    import type { ExistingCredential } from './CredentialEditor.svelte'

    type ProtocolID =
        | 'http'
        | 'ssh'
        | 'mysql'
        | 'postgres'
        | 'kubernetes'
        | 'vnc'
        | 'rdp'

    interface Props {
        value: UserRequireCredentialsPolicy
        possibleCredentials: Set<CredentialKind>
        existingCredentials: ExistingCredential[]
        protocolId: ProtocolID
    }

    let {
        value = $bindable(),
        possibleCredentials,
        existingCredentials,
        protocolId,
    }: Props = $props()

    const labels = {
        Password: 'Password',
        PublicKey: 'Key',
        Certificate: 'Certificate',
        Totp: 'OTP',
        Sso: 'SSO',
        WebUserApproval: 'In-browser auth',
    }

    const requirePassword = $derived(
        protocolId === 'vnc' || protocolId === 'rdp',
    )

    const tips: Record<ProtocolID, Map<[CredentialKind, boolean], string>> = {
        postgres: new Map([
            [
                [CredentialKind.WebUserApproval, true],
                'Not all clients will show the 2FA auth prompt. The user might need to log in to the Warpgate UI to see the prompt.',
            ],
        ]),
        http: new Map(),
        mysql: new Map(),
        ssh: new Map(),
        vnc: new Map([
            [
                [CredentialKind.WebUserApproval, true],
                'The client is shown a link to approve the login in the browser, and is held on a waiting screen until confirmed.',
            ],
        ]),
        rdp: new Map(),
        kubernetes: new Map([
            [
                [CredentialKind.WebUserApproval, true],
                'Users will need to log in to the Warpgate UI to see the 2FA auth prompt for Kubernetes access.',
            ],
        ]),
    }

    let activeTips: string[] = $derived.by(() => {
        let result = []
        for (const [[kind, enabled], tip] of tips[protocolId]?.entries() ??
            []) {
            if (value[protocolId]?.includes(kind) === enabled) {
                result.push(tip)
            }
        }
        return result
    })

    const validCredentials = $derived.by(() => {
        const vc = new SvelteSet(
            existingCredentials.map(x => x.kind as CredentialKind),
        )
        vc.add(CredentialKind.WebUserApproval)
        return vc
    })

    let isAny = $derived(!value[protocolId])

    // Keep the password credential present in any explicit policy when it's mandatory.
    $effect(() => {
        if (
            requirePassword &&
            value[protocolId] &&
            !value[protocolId].includes(CredentialKind.Password)
        ) {
            value[protocolId] = [CredentialKind.Password, ...value[protocolId]]
        }
    })

    function updateAny() {
        if (isAny) {
            value[protocolId] = undefined
        } else if (requirePassword) {
            value[protocolId] = [CredentialKind.Password]
        } else {
            value[protocolId] = []
            let oneCred = Array.from(validCredentials).find(x =>
                possibleCredentials.has(x),
            )
            if (oneCred) {
                value[protocolId] = [oneCred]
            }
        }
    }

    function toggle(type: CredentialKind) {
        // Password is mandatory when required by this protocol.
        if (requirePassword && type === CredentialKind.Password) {
            return
        }
        if (!value[protocolId]) {
            return
        }
        if (value[protocolId].includes(type)) {
            value[protocolId] = value[protocolId].filter(
                (x: CredentialKind) => x !== type,
            )
        } else {
            value[protocolId].push(type)
        }
    }
</script>

<div class="d-flex wrapper">
    <Input
        id={`policy-editor-${protocolId}`}
        type="switch"
        bind:checked={isAny}
        label="Any credential"
        on:change={updateAny}
    />
    {#if !isAny}
        {#each [...validCredentials] as type (type)}
            {#if possibleCredentials.has(type)}
                <Input
                    id={`policy-editor-${protocolId}${type}`}
                    type="switch"
                    checked={value[protocolId]?.includes(type) || (requirePassword && type === CredentialKind.Password)}
                    disabled={requirePassword && type === CredentialKind.Password}
                    label={labels[type]}
                    on:change={() => toggle(type)}
                />
            {/if}
        {/each}
    {/if}
</div>

{#each activeTips as tip (tip)}
    <InfoBox class="mt-2">{tip}</InfoBox>
{/each}

<style lang="scss">
    .wrapper {
        flex-wrap: wrap;
        :global(.form-switch) {
            margin-right: 1rem;
        }
    }
</style>
