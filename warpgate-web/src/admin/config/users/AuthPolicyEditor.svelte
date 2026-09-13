<script lang="ts">
    import {
        faPlus,
        faTimes,
        faTrash,
        faWarning,
    } from '@fortawesome/free-solid-svg-icons'
    import { Button, Input, Tooltip } from '@sveltestrap/sveltestrap'
    import {
        CredentialKind,
        type ParameterValues,
        type UserRequireCredentialsPolicy,
    } from 'admin/lib/api'
    import InfoBox from 'common/InfoBox.svelte'
    import {
        getEffectivePossibleCredentials,
        type ProtocolID,
    } from 'common/protocols'
    import { SvelteSet } from 'svelte/reactivity'
    import Fa from 'svelte-fa'
    import type { ExistingCredential } from './CredentialEditor.svelte'

    interface PolicyProtocol {
        id: ProtocolID
        name: string
    }

    interface Props {
        value: UserRequireCredentialsPolicy
        existingCredentials?: ExistingCredential[]
        globalParameters?: ParameterValues
    }

    let {
        value = $bindable(),
        existingCredentials,
        globalParameters,
    }: Props = $props()

    const protocols: PolicyProtocol[] = [
        { id: 'ssh', name: 'SSH' },
        { id: 'http', name: 'HTTP' },
        { id: 'mysql', name: 'MySQL' },
        { id: 'postgres', name: 'PostgreSQL' },
        { id: 'kubernetes', name: 'Kubernetes' },
        { id: 'vnc', name: 'VNC' },
        { id: 'rdp', name: 'RDP' },
    ]

    const possibleCredentialsByProtocol = $derived(
        new Map(
            protocols.map(p => [
                p.id,
                getEffectivePossibleCredentials(p.id, globalParameters),
            ]),
        ),
    )

    function possibleCredentials(protocol: ProtocolID): Set<CredentialKind> {
        return possibleCredentialsByProtocol.get(protocol) ?? new Set()
    }

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

    const availableKinds = $derived.by<SvelteSet<CredentialKind> | undefined>(
        () => {
            if (!existingCredentials) {
                return undefined
            }
            const s = new SvelteSet(
                existingCredentials.map(x => x.kind as CredentialKind),
            )
            s.add(CredentialKind.WebUserApproval)
            return s
        },
    )

    // see Parameters::Model::mfa_required_factor
    function mfaEnforcedFactor(protocolId: ProtocolID): CredentialKind | null {
        if (!globalParameters || globalParameters.mfaEnforcement === 'Off') {
            return null
        }
        const hasSso =
            existingCredentials?.some(x => x.kind === CredentialKind.Sso) ??
            false
        if (globalParameters.mfaPolicyExemptSsoUsers && hasSso) {
            return null
        }
        const hasTotp =
            existingCredentials?.some(x => x.kind === CredentialKind.Totp) ??
            false
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

    function getCombinations(
        protocolId: ProtocolID,
    ): CredentialKind[][] | undefined {
        const val = value[protocolId] as unknown
        if (!val || !Array.isArray(val)) {
            return undefined
        }
        if (val.length === 0) {
            return []
        }
        if (typeof val[0] === 'string') {
            return [val as CredentialKind[]]
        }
        return val as CredentialKind[][]
    }

    function shownKinds(
        protocol: PolicyProtocol,
    ): { kind: CredentialKind; label: string }[] {
        const combos = getCombinations(protocol.id) ?? []
        const kindsInUse = new Set(combos.flat())
        return credentialKinds.filter(
            ({ kind }) =>
                possibleCredentials(protocol.id).has(kind) ||
                kindsInUse.has(kind) ||
                mfaEnforcedFactor(protocol.id) === kind,
        )
    }

    function activeTipsFor(protocol: PolicyProtocol): string[] {
        const result = []
        const combos = getCombinations(protocol.id) ?? []
        const kindsInUse = new Set(combos.flat())
        for (const [[kind, enabled], tip] of tips[protocol.id].entries()) {
            const effective =
                kindsInUse.has(kind) || mfaEnforcedFactor(protocol.id) === kind
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
            if (!requiresPassword(protocol.id)) {
                continue
            }
            const combos = getCombinations(protocol.id)
            if (!combos) {
                continue
            }
            let changed = false
            const updated = combos.map(combo => {
                if (!combo.includes(CredentialKind.Password)) {
                    changed = true
                    return [CredentialKind.Password, ...combo]
                }
                return combo
            })
            if (changed) {
                value[protocol.id] = updated
            }
        }
    })

    function toggleAny(protocol: PolicyProtocol) {
        if (value[protocol.id]) {
            value[protocol.id] = undefined
        } else if (requiresPassword(protocol.id)) {
            value[protocol.id] = [[CredentialKind.Password]]
        } else {
            const possible = possibleCredentials(protocol.id)
            const oneCred =
                Array.from(availableKinds ?? []).find(x => possible.has(x)) ??
                Array.from(possible)[0] ??
                CredentialKind.Password
            value[protocol.id] = [[oneCred]]
        }
    }

    function addCombination(protocolId: ProtocolID) {
        const combos = getCombinations(protocolId) ?? []
        let defaultKind: CredentialKind = CredentialKind.Password
        if (!requiresPassword(protocolId)) {
            const possible = possibleCredentials(protocolId)
            const oneCred =
                Array.from(availableKinds ?? []).find(x => possible.has(x)) ??
                Array.from(possible)[0]
            if (oneCred) {
                defaultKind = oneCred
            }
        }
        value[protocolId] = [...combos, [defaultKind]]
    }

    function removeCombination(protocolId: ProtocolID, comboIndex: number) {
        const combos = getCombinations(protocolId)
        if (!combos) {
            return
        }
        const updated = combos.filter((_, i) => i !== comboIndex)
        if (updated.length === 0) {
            value[protocolId] = undefined
        } else {
            value[protocolId] = updated
        }
    }

    function addFactor(
        protocolId: ProtocolID,
        comboIndex: number,
        kind: CredentialKind,
    ) {
        const combos = getCombinations(protocolId)
        if (!combos?.[comboIndex]) {
            return
        }
        const combo = combos[comboIndex]
        if (!combo.includes(kind)) {
            combos[comboIndex] = [...combo, kind]
            value[protocolId] = [...combos]
        }
    }

    function removeFactor(
        protocolId: ProtocolID,
        comboIndex: number,
        factorIndex: number,
    ) {
        const combos = getCombinations(protocolId)
        if (!combos?.[comboIndex]) {
            return
        }
        const combo = combos[comboIndex]
        const kind = combo[factorIndex]
        if (requiresPassword(protocolId) && kind === CredentialKind.Password) {
            return
        }
        if (combo.length <= 1) {
            return
        }
        combos[comboIndex] = combo.filter((_, i) => i !== factorIndex)
        value[protocolId] = [...combos]
    }

    function changeFactor(
        protocolId: ProtocolID,
        comboIndex: number,
        factorIndex: number,
        newKind: CredentialKind,
    ) {
        const combos = getCombinations(protocolId)
        if (!combos?.[comboIndex]) {
            return
        }
        const combo = combos[comboIndex]
        const oldKind = combo[factorIndex]
        if (
            requiresPassword(protocolId) &&
            oldKind === CredentialKind.Password &&
            newKind !== CredentialKind.Password
        ) {
            return
        }
        if (combo.includes(newKind)) {
            return
        }
        combos[comboIndex] = combo.map((k, i) =>
            i === factorIndex ? newKind : k,
        )
        value[protocolId] = [...combos]
    }

    function availableKindsForFactor(
        protocol: PolicyProtocol,
        combo: CredentialKind[],
        currentKind: CredentialKind,
    ): { kind: CredentialKind; label: string }[] {
        return shownKinds(protocol).filter(
            ({ kind }) => kind === currentKind || !combo.includes(kind),
        )
    }

    function unselectedKinds(
        protocol: PolicyProtocol,
        combo: CredentialKind[],
    ): { kind: CredentialKind; label: string }[] {
        return shownKinds(protocol).filter(({ kind }) => !combo.includes(kind))
    }
</script>

{#if globalParameters && globalParameters.mfaEnforcement !== 'Off'}
    {#if globalParameters.mfaPolicyExemptSsoUsers && existingCredentials?.some(x => x.kind === CredentialKind.Sso)}
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
        {@const combos = getCombinations(protocol.id)}
        {@const tips = activeTipsFor(protocol)}
        <div class="list-group-item">
            <div class="d-flex align-items-center">
                <strong>{protocol.name}</strong>
                {#if possibleCredentials(protocol.id).size > 0 || (combos && combos.length > 0)}
                    <Input
                        type="checkbox"
                        id={`policy-editor-${protocol.id}`}
                        class="mb-0 ms-auto"
                        label="Any credential"
                        checked={!combos}
                        on:change={() => toggleAny(protocol)}
                    />
                {:else}
                    <span class="text-muted ms-auto">
                        No authentication methods available
                    </span>
                {/if}
            </div>

            {#if combos}
                <div class="mt-2 mb-2 d-flex flex-column gap-2">
                    {#each combos as combo, comboIndex (comboIndex)}
                        {#if comboIndex > 0}
                            <div class="d-flex align-items-center my-1">
                                <hr
                                    class="flex-grow-1 my-0 text-muted opacity-25"
                                >
                                <span
                                    class="badge bg-secondary-subtle text-secondary-emphasis border mx-2 px-2 py-1 small fw-semibold"
                                >
                                    OR
                                </span>
                                <hr
                                    class="flex-grow-1 my-0 text-muted opacity-25"
                                >
                            </div>
                        {/if}

                        <div
                            class="d-flex flex-wrap align-items-center gap-2 p-2 border rounded bg-body-tertiary"
                        >
                            <span class="text-muted small fw-bold me-1">
                                #{comboIndex + 1}
                            </span>

                            {#each combo as kind, factorIndex (`${comboIndex}-${factorIndex}-${kind}`)}
                                {@const mandatory =
                                    requiresPassword(protocol.id) &&
                                    kind === CredentialKind.Password}
                                {@const missingCredential =
                                    availableKinds && !availableKinds.has(kind)}
                                {@const unsupported =
                                    !possibleCredentials(protocol.id).has(kind)}
                                {@const factorId = `factor-${protocol.id}-${comboIndex}-${factorIndex}`}

                                {#if factorIndex > 0}
                                    <span
                                        class="badge bg-primary-subtle text-primary border px-2 py-1 small fw-semibold"
                                    >
                                        AND
                                    </span>
                                {/if}

                                <div
                                    class="d-inline-flex align-items-center border rounded bg-body px-2 py-1 gap-1"
                                    id={factorId}
                                >
                                    <select
                                        class="form-select form-select-sm border-0 py-0 ps-1 pe-4 shadow-none bg-transparent"
                                        style="width: auto; cursor: pointer;"
                                        value={kind}
                                        disabled={mandatory}
                                        on:change={(e) => {
                                            const target = e.currentTarget as HTMLSelectElement
                                            changeFactor(protocol.id, comboIndex, factorIndex, target.value as CredentialKind)
                                        }}
                                    >
                                        {#each availableKindsForFactor(protocol, combo, kind) as opt (opt.kind)}
                                            <option value={opt.kind}>
                                                {opt.label}
                                            </option>
                                        {/each}
                                    </select>

                                    {#if missingCredential || unsupported}
                                        <Fa
                                            icon={faWarning}
                                            class="text-warning small"
                                        />
                                    {/if}

                                    {#if !mandatory && combo.length > 1}
                                        <button
                                            type="button"
                                            class="btn btn-link text-muted p-0 ms-1 border-0"
                                            style="line-height: 1;"
                                            title="Remove factor"
                                            on:click={() => removeFactor(protocol.id, comboIndex, factorIndex)}
                                        >
                                            <Fa icon={faTimes} />
                                        </button>
                                    {/if}

                                    {#if mandatory || missingCredential || unsupported}
                                        <Tooltip
                                            target={factorId}
                                            animation
                                            delay="250"
                                        >
                                            {#if mandatory}
                                                <div>
                                                    This protocol always
                                                    requires a password.
                                                </div>
                                            {/if}
                                            {#if missingCredential}
                                                <div>
                                                    The user has no credential
                                                    of this kind yet.
                                                </div>
                                            {/if}
                                            {#if unsupported}
                                                <div>
                                                    Not supported by this
                                                    protocol.
                                                </div>
                                            {/if}
                                        </Tooltip>
                                    {/if}
                                </div>
                            {/each}

                            {#if unselectedKinds(protocol, combo).length > 0}
                                <select
                                    class="form-select form-select-sm py-0 ps-2 pe-4 shadow-none text-muted"
                                    style="width: auto; height: 31px; cursor: pointer; border-style: dashed;"
                                    value=""
                                    on:change={(e) => {
                                        const target = e.currentTarget as HTMLSelectElement
                                        if (target.value) {
                                            addFactor(protocol.id, comboIndex, target.value as CredentialKind)
                                            target.value = ''
                                        }
                                    }}
                                >
                                    <option value="" disabled selected>
                                        + Factor
                                    </option>
                                    {#each unselectedKinds(protocol, combo) as opt (opt.kind)}
                                        <option value={opt.kind}>
                                            + {opt.label}
                                        </option>
                                    {/each}
                                </select>
                            {/if}

                            <div class="ms-auto">
                                <Button
                                    color="link"
                                    size="sm"
                                    class="text-danger p-1"
                                    disabled={combos.length <= 1}
                                    title="Delete combination"
                                    on:click={() => removeCombination(protocol.id, comboIndex)}
                                >
                                    <Fa icon={faTrash} />
                                </Button>
                            </div>
                        </div>
                    {/each}

                    <div>
                        <Button
                            color="secondary"
                            outline
                            size="sm"
                            class="d-inline-flex align-items-center gap-1 mt-1"
                            on:click={() => addCombination(protocol.id)}
                        >
                            <Fa icon={faPlus} />
                            <span>Add combination</span>
                        </Button>
                    </div>
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
