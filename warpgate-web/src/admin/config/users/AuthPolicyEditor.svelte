<script lang="ts">
    import { faWarning } from '@fortawesome/free-solid-svg-icons'
    import { Input, Tooltip } from '@sveltestrap/sveltestrap'
    import {
        CredentialKind,
        type ParameterValues,
        type UserRequireCredentialsPolicy,
    } from 'admin/lib/api'
    import InfoBox from 'common/InfoBox.svelte'
    import { SvelteSet } from 'svelte/reactivity'
    import Fa from 'svelte-fa'
    import type { ExistingCredential } from './CredentialEditor.svelte'

    type ProtocolID =
        | 'http'
        | 'ssh'
        | 'mysql'
        | 'postgres'
        | 'kubernetes'
        | 'vnc'
        | 'rdp'

    interface PolicyProtocol {
        id: ProtocolID
        name: string
        possibleCredentials: Set<CredentialKind>
    }

    interface Props {
        value: UserRequireCredentialsPolicy
        existingCredentials: ExistingCredential[]
        protocols: PolicyProtocol[]
        globalParameters?: ParameterValues
    }

    let {
        value = $bindable(),
        existingCredentials,
        protocols,
        globalParameters,
    }: Props = $props()

    const credentialKinds: { kind: CredentialKind; label: string }[] = [
        { kind: CredentialKind.Password, label: 'Password' },
        { kind: CredentialKind.PublicKey, label: 'Key' },
        { kind: CredentialKind.Certificate, label: 'Certificate' },
        { kind: CredentialKind.Totp, label: 'OTP' },
        { kind: CredentialKind.Sso, label: 'SSO' },
        { kind: CredentialKind.WebUserApproval, label: 'In-browser auth' },
    ]

    const requiresPassword = (id: ProtocolID) => id === 'vnc' || id === 'rdp'

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
        rdp: new Map([
            [
                [CredentialKind.WebUserApproval, true],
                'The client is shown a link to approve the login in the browser, and is held on a waiting screen until confirmed.',
            ],
        ]),
        kubernetes: new Map([
            [
                [CredentialKind.WebUserApproval, true],
                'Users will need to log in to the Warpgate UI to see the 2FA auth prompt for Kubernetes access.',
            ],
        ]),
    }

    const availableKinds = $derived.by(() => {
        const s = new SvelteSet(
            existingCredentials.map(x => x.kind as CredentialKind),
        )
        s.add(CredentialKind.WebUserApproval)
        return s
    })

    // see Parameters::Model::mfa_required_factor
    function mfaEnforcedFactor(protocolId: ProtocolID): CredentialKind | null {
        if (!globalParameters || globalParameters.mfaEnforcement === 'Off') {
            return null
        }
        const hasSso = existingCredentials.some(
            x => x.kind === CredentialKind.Sso,
        )
        if (globalParameters.mfaPolicyExemptSsoUsers && hasSso) {
            return null
        }
        const hasTotp = existingCredentials.some(
            x => x.kind === CredentialKind.Totp,
        )
        if (protocolId === 'http') {
            return hasTotp ? CredentialKind.Totp : null
        }
        if (globalParameters.mfaEnforcement !== 'Require') {
            return null
        }
        if (
            protocolId === 'ssh' ||
            protocolId === 'vnc' ||
            protocolId === 'rdp'
        ) {
            return hasTotp
                ? CredentialKind.Totp
                : CredentialKind.WebUserApproval
        }
        return CredentialKind.WebUserApproval
    }

    function shownKinds(
        protocol: PolicyProtocol,
    ): { kind: CredentialKind; label: string }[] {
        return credentialKinds.filter(
            ({ kind }) =>
                protocol.possibleCredentials.has(kind) ||
                (value[protocol.id]?.includes(kind) ?? false) ||
                mfaEnforcedFactor(protocol.id) === kind,
        )
    }

    function activeTipsFor(protocol: PolicyProtocol): string[] {
        const result = []
        for (const [[kind, enabled], tip] of tips[protocol.id].entries()) {
            const effective =
                (value[protocol.id]?.includes(kind) ?? false) ||
                mfaEnforcedFactor(protocol.id) === kind
            if (effective === enabled) {
                result.push(tip)
            }
        }
        return result
    }

    // Keep the password credential present in any explicit policy when the
    // protocol mandates it.
    $effect(() => {
        for (const protocol of protocols) {
            const kinds = value[protocol.id]
            if (
                requiresPassword(protocol.id) &&
                kinds &&
                !kinds.includes(CredentialKind.Password)
            ) {
                value[protocol.id] = [CredentialKind.Password, ...kinds]
            }
        }
    })

    function toggleAny(protocol: PolicyProtocol) {
        if (value[protocol.id]) {
            value[protocol.id] = undefined
        } else if (requiresPassword(protocol.id)) {
            value[protocol.id] = [CredentialKind.Password]
        } else {
            const oneCred = Array.from(availableKinds).find(x =>
                protocol.possibleCredentials.has(x),
            )
            value[protocol.id] = oneCred ? [oneCred] : []
        }
    }

    function toggle(protocolId: ProtocolID, kind: CredentialKind) {
        // Password is mandatory when required by this protocol.
        if (requiresPassword(protocolId) && kind === CredentialKind.Password) {
            return
        }
        const kinds = value[protocolId]
        if (!kinds) {
            return
        }
        if (kinds.includes(kind)) {
            const remaining = kinds.filter(x => x !== kind)
            // An explicit policy with nothing selected means "any credential"
            value[protocolId] = remaining.length ? remaining : undefined
        } else {
            kinds.push(kind)
        }
    }
</script>

{#if globalParameters && globalParameters.mfaEnforcement !== 'Off'}
    {#if globalParameters.mfaPolicyExemptSsoUsers && existingCredentials.some(x => x.kind === CredentialKind.Sso)}
        <InfoBox>
            MFA enforcement is on, but is set to exempt this user from MFA
            requirements because they have an SSO credential.
        </InfoBox>
    {:else}
        <InfoBox>
            MFA enforcement is on: an OTP or an in-browser approval will be
            required in addition to this policy
        </InfoBox>
    {/if}
{/if}

<div class="list-group list-group-flush mb-3">
    {#each protocols as protocol (protocol.id)}
        {@const tips = activeTipsFor(protocol)}
        <div class="list-group-item">
            <div class="d-flex align-items-center">
                <strong>{protocol.name}</strong>
                {#if protocol.possibleCredentials.size > 0 || value[protocol.id]?.length}
                    <Input
                        type="checkbox"
                        id={`policy-editor-${protocol.id}`}
                        class="mb-0 ms-auto"
                        label="Any credential"
                        checked={!value[protocol.id]}
                        on:change={() => toggleAny(protocol)}
                    />
                {:else}
                    <span class="text-muted ms-auto">
                        No authentication methods available
                    </span>
                {/if}
            </div>
            {#if value[protocol.id]}
                <div class="d-flex flex-wrap gap-3 mt-2 mb-2">
                    {#each shownKinds(protocol) as { kind, label } (kind)}
                        {@const enabled =
                            value[protocol.id]?.includes(kind) ?? false}
                        {@const mandatory =
                            requiresPassword(protocol.id) &&
                            kind === CredentialKind.Password}
                        {@const enforced =
                            mfaEnforcedFactor(protocol.id) === kind}
                        {@const missingCredential =
                            enabled && !availableKinds.has(kind)}
                        {@const unsupported =
                            (enabled || enforced) &&
                            !protocol.possibleCredentials.has(kind)}
                        <div
                            class="d-flex align-items-center gap-2"
                            id={`policy-editor-${protocol.id}${kind}-wrap`}
                        >
                            <Input
                                id={`policy-editor-${protocol.id}${kind}`}
                                class="mb-0"
                                type="checkbox"
                                {label}
                                checked={enabled || mandatory || enforced}
                                disabled={mandatory || enforced}
                                on:change={() => toggle(protocol.id, kind)}
                            />
                            {#if missingCredential || unsupported}
                                <Fa icon={faWarning} class="text-warning" />
                            {/if}
                            {#if mandatory || enforced || missingCredential || unsupported}
                                <Tooltip
                                    target={`policy-editor-${protocol.id}${kind}-wrap`}
                                    animation
                                    delay="250"
                                >
                                    {#if mandatory}
                                        <div>
                                            This protocol always requires a
                                            password.
                                        </div>
                                    {/if}
                                    {#if enforced}
                                        <div>
                                            Required by global MFA enforcement.
                                        </div>
                                    {/if}
                                    {#if missingCredential}
                                        <div>
                                            The user has no credential of this
                                            kind yet.
                                        </div>
                                    {/if}
                                    {#if unsupported}
                                        <div>
                                            Not supported by this protocol.
                                        </div>
                                    {/if}
                                </Tooltip>
                            {/if}
                        </div>
                    {/each}
                </div>
            {/if}
            {#if tips.length}
                <div class="mt-3 mb-2">
                    {#each tips as tip (tip)}
                        <InfoBox class="mt-2">{tip}</InfoBox>
                    {/each}
                </div>
            {/if}
        </div>
    {/each}
</div>
