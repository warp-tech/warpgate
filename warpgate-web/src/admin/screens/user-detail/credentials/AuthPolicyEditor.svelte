<script lang="ts">
    /**
     * Per-protocol authentication policy — screen 6c.
     *
     * ── Enumeration of the old component, asserted present here ──────────
     * Data:      protocols (7), credentialKinds (6), tips (per protocol/kind),
     *            possibleCredentialsByProtocol, availableKinds
     * Predicates: requiresPassword (vnc|rdp), mfaEnforcedFactor, shownKinds,
     *            activeTipsFor
     * Mutations: toggleAny, toggle, and the $effect that re-inserts Password
     * Renders:   MFA enforcement notice (2 variants), per-protocol row,
     *            "Any credential" checkbox, per-kind checkboxes, warning
     *            markers with 4 distinct tooltip reasons, per-protocol tips
     *
     * ── Semantics that are easy to get wrong ─────────────────────────────
     * **An explicit policy with no kinds selected means "any credential".**
     * `value[protocol]` being `undefined` is the permissive state; an array is
     * the restrictive one. So:
     *   - the "Any credential" checkbox is INVERTED: checked when there is no
     *     policy
     *   - unchecking the last kind in `toggle` sets the policy back to
     *     `undefined` rather than to `[]`, because an empty array would read
     *     as "no credential can authenticate" and lock the user out
     *
     * VNC and RDP always require a password at the protocol level, so it is
     * force-included by an effect and its checkbox is disabled — unchecking it
     * would produce a policy the server cannot honour.
     *
     * `mfaEnforcedFactor` mirrors `Parameters::Model::mfa_required_factor` on
     * the server. If the two drift, this editor shows a policy that is not the
     * one being enforced, so it is worth diffing against the Rust when either
     * changes.
     *
     * Two warning states are distinct and both matter:
     *   - *missing credential*: the policy names a kind the user does not have,
     *     so they cannot satisfy it
     *   - *unsupported*: the policy names a kind the protocol cannot carry
     * Either makes the policy unsatisfiable, and neither is an error the
     * server will reject at save time.
     */
    import {
        CredentialKind,
        type ParameterValues,
        type UserRequireCredentialsPolicy,
    } from 'admin/lib/api'
    import {
        getEffectivePossibleCredentials,
        type ProtocolID,
    } from 'common/protocols'
    import { SvelteSet } from 'svelte/reactivity'
    import Callout from 'ui/Callout.svelte'
    import Checkbox from 'ui/Checkbox.svelte'
    import Tooltip from 'ui/Tooltip.svelte'
    import type { ExistingCredential } from './CredentialEditor.svelte'
    import 'ui/markers.css'

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
                'Not all clients will show the 2FA auth prompt. The user might need to log in to the Warpgate UI to see it.',
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
            // In-browser approval needs no stored credential.
            s.add(CredentialKind.WebUserApproval)
            return s
        },
    )

    // Mirrors Parameters::Model::mfa_required_factor on the server.
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

    function shownKinds(
        protocol: PolicyProtocol,
    ): { kind: CredentialKind; label: string }[] {
        return credentialKinds.filter(
            ({ kind }) =>
                possibleCredentials(protocol.id).has(kind) ||
                (value[protocol.id]?.includes(kind) ?? false) ||
                mfaEnforcedFactor(protocol.id) === kind,
        )
    }

    function activeTipsFor(protocol: PolicyProtocol): string[] {
        const result: string[] = []
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

    // Keeps Password in any explicit policy for a protocol that mandates it.
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
            // undefined is the permissive state, not []
            value[protocol.id] = undefined
        } else if (requiresPassword(protocol.id)) {
            value[protocol.id] = [CredentialKind.Password]
        } else {
            const possible = possibleCredentials(protocol.id)
            const oneCred = Array.from(availableKinds ?? []).find(x =>
                possible.has(x),
            )
            value[protocol.id] = oneCred ? [oneCred] : []
        }
    }

    function toggle(protocolId: ProtocolID, kind: CredentialKind) {
        if (requiresPassword(protocolId) && kind === CredentialKind.Password) {
            return
        }
        const kinds = value[protocolId]
        if (!kinds) {
            return
        }
        if (kinds.includes(kind)) {
            const remaining = kinds.filter(x => x !== kind)
            // Empty would read as "nothing can authenticate" and lock the user
            // out; undefined is "any credential".
            value[protocolId] = remaining.length ? remaining : undefined
        } else {
            kinds.push(kind)
        }
    }

    const ssoExempt = $derived(
        !!globalParameters?.mfaPolicyExemptSsoUsers &&
            (existingCredentials?.some(x => x.kind === CredentialKind.Sso) ??
                false),
    )
</script>

{#if globalParameters && globalParameters.mfaEnforcement !== 'Off'}
    <div class="mfa-notice">
        {#if ssoExempt}
            <Callout title="MFA enforcement is on, and this user is exempt">
                Global enforcement exempts users who have an SSO credential, and
                this user has one. The policy below applies as written.
            </Callout>
        {:else}
            <Callout title="MFA enforcement is on">
                An OTP or an in-browser approval is required in addition to
                whatever the policy below says.
            </Callout>
        {/if}
    </div>
{/if}

<ul class="protocols">
    {#each protocols as protocol (protocol.id)}
        {@const activeTips = activeTipsFor(protocol)}
        {@const hasAnyMethod =
            possibleCredentials(protocol.id).size > 0 ||
            !!value[protocol.id]?.length}
        <li>
            <div class="proto-head">
                <span class="proto-name">{protocol.name}</span>
                {#if hasAnyMethod}
                    <!-- Inverted: checked means no explicit policy -->
                    <Checkbox
                        label="Any credential"
                        checked={!value[protocol.id]}
                        onchange={() => toggleAny(protocol)}
                    />
                {:else}
                    <span class="proto-none">
                        No authentication methods available
                    </span>
                {/if}
            </div>

            {#if value[protocol.id]}
                <div class="kinds">
                    {#each shownKinds(protocol) as { kind, label } (kind)}
                        {@const enabled =
                            value[protocol.id]?.includes(kind) ?? false}
                        {@const mandatory =
                            requiresPassword(protocol.id) &&
                            kind === CredentialKind.Password}
                        {@const enforced =
                            mfaEnforcedFactor(protocol.id) === kind}
                        {@const missingCredential =
                            enabled && availableKinds && !availableKinds.has(kind)}
                        {@const unsupported =
                            (enabled || enforced) &&
                            !possibleCredentials(protocol.id).has(kind)}
                        {@const reason = mandatory
                            ? 'This protocol always requires a password.'
                            : enforced
                              ? 'Required by global MFA enforcement.'
                              : missingCredential
                                ? 'The user has no credential of this kind yet, so this policy cannot be satisfied.'
                                : unsupported
                                  ? 'Not supported by this protocol, so this policy cannot be satisfied.'
                                  : ''}
                        <div class="kind">
                            {#if reason}
                                <Tooltip text={reason}>
                                    <span class="kind-inner">
                                        <Checkbox
                                            {label}
                                            checked={enabled ||
                                                mandatory ||
                                                enforced}
                                            disabled={mandatory || enforced}
                                            onchange={() =>
                                                toggle(protocol.id, kind)}
                                        />
                                        {#if missingCredential || unsupported}
                                            <span
                                                class="wg-marker wg-marker-diamond warn-marker"
                                                style="--marker: var(--wg-secondary)"
                                                aria-hidden="true"
                                            ></span>
                                        {/if}
                                    </span>
                                </Tooltip>
                            {:else}
                                <Checkbox
                                    {label}
                                    checked={enabled}
                                    onchange={() => toggle(protocol.id, kind)}
                                />
                            {/if}
                        </div>
                    {/each}
                </div>
            {/if}

            {#each activeTips as tip (tip)}
                <div class="tip">
                    <Callout>{tip}</Callout>
                </div>
            {/each}
        </li>
    {/each}
</ul>

<style>
    .mfa-notice {
        margin-bottom: var(--wg-space-md);
    }

    .protocols {
        list-style: none;
        margin: 0;
        padding: 0;
        border: var(--wg-border-width) solid var(--wg-border);
        border-radius: var(--wg-radius-panel);
        overflow: hidden;
    }

    .protocols li {
        padding: var(--wg-space-md);
        border-bottom: var(--wg-border-width) solid var(--wg-border);
    }

    .protocols li:last-child {
        border-bottom: 0;
    }

    .proto-head {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: var(--wg-space-lg);
    }

    .proto-name {
        font: var(--wg-text-label-md);
        color: var(--wg-text);
    }

    .proto-none {
        font: var(--wg-text-label-sm);
        color: var(--wg-text-subtle);
    }

    .kinds {
        display: flex;
        flex-wrap: wrap;
        gap: var(--wg-space-lg);
        margin-top: var(--wg-space-md);
    }

    .kind-inner {
        display: inline-flex;
        align-items: center;
        gap: var(--wg-space-xs);
    }

    /* The marker repeats what the tooltip says, for anyone not hovering */
    .warn-marker {
        flex: none;
    }

    .tip {
        margin-top: var(--wg-space-md);
    }

    @media (max-width: 560px) {
        .proto-head {
            flex-direction: column;
            align-items: flex-start;
            gap: var(--wg-space-sm);
        }
    }
</style>
