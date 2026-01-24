<script lang="ts">
import { Input } from '@sveltestrap/sveltestrap'
import { CredentialKind, type UserRequireCredentialsPolicy } from './lib/api'
import type { ExistingCredential } from './CredentialEditor.svelte'
import InfoBox from 'common/InfoBox.svelte'
import { SvelteSet } from 'svelte/reactivity'

type ProtocolID = 'http' | 'ssh' | 'mysql' | 'postgres'

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
    Totp: 'OTP',
    Sso: 'SSO',
    WebUserApproval: 'In-browser auth',
}

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
}

let activeTips: string[] = $derived.by(() => {
    let result = []
    for (const [[kind, enabled], tip] of tips[protocolId]?.entries() ?? []) {
        if (value[protocolId]?.includes(kind) === enabled) {
            result.push(tip)
        }
    }
    return result
})

const validCredentials = $derived.by(() => {
    const vc = new SvelteSet(existingCredentials.map(x => x.kind as CredentialKind))
    vc.add(CredentialKind.WebUserApproval)
    return vc
})

let isAny = $derived(!value[protocolId])

function updateAny () {
    if (isAny) {
        value[protocolId] = undefined
    } else {
        value[protocolId] = []
        let oneCred = Array.from(validCredentials).find(x => possibleCredentials.has(x))
        if (oneCred) {
            value[protocolId] = [oneCred]
        }
    }
}

function toggle (type: CredentialKind) {
    if (value[protocolId]!.includes(type)) {
        value[protocolId] = value[protocolId]!.filter((x: CredentialKind) => x !== type)
    } else {
        value[protocolId]!.push(type)
    }
}
</script>

<div class="d-flex wrapper">
    <Input
        id={'policy-editor-' + protocolId}
        type="switch"
        bind:checked={isAny}
        label="Any credential"
        on:change={updateAny}
    />
    {#if !isAny}
        {#each [...validCredentials] as type (type)}
            {#if possibleCredentials.has(type)}
                <Input
                    id={'policy-editor-' + protocolId + type}
                    type="switch"
                    checked={value[protocolId]?.includes(type)}
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
