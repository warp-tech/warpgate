<script lang="ts">
import { Input } from 'sveltestrap'

import { CredentialKind, User, UserRequireCredentialsPolicy } from './lib/api'

export let user: User
export let value: UserRequireCredentialsPolicy
export let possibleCredentials: Set<CredentialKind>
export let protocolId: string

const labels = {
    Password: 'Password',
    PublicKey: 'Key',
    Totp: 'OTP',
    Sso: 'SSO',
    WebUserApproval: 'In-browser auth',
}

let isAny = false
let validCredentials = new Set<CredentialKind>()

$: {
    validCredentials = new Set(user.credentials.map(x => x.kind as CredentialKind))
    validCredentials.add(CredentialKind.WebUserApproval)

    setTimeout(() => {
        isAny = !value[protocolId]
    })
}

function updateAny () {
    setTimeout(() => {
        if (isAny) {
            value[protocolId] = undefined
        } else {
            value[protocolId] = []
            let oneCred = Array.from(validCredentials).filter(x => possibleCredentials.has(x))[0]
            if (oneCred) {
                value[protocolId] = [oneCred]
            }
        }
    })
}

function toggle (type: string) {
    if (value[protocolId].includes(type)) {
        value[protocolId] = value[protocolId].filter((x: CredentialKind) => x !== type)
    } else {
        value[protocolId].push(type)
    }
}
</script>

<div class="d-flex wrapper">
    <Input
        id={'policy-editor-' + user.username + protocolId}
        type="switch"
        bind:checked={isAny}
        label="Any credential"
        on:change={updateAny}
    />
    {#if !isAny}
        {#each [...validCredentials] as type}
            {#if possibleCredentials.has(type)}
                <Input
                    id={'policy-editor-' + user.username + protocolId + type}
                    type="switch"
                    checked={value[protocolId]?.includes(type)}
                    label={labels[type]}
                    on:change={() => toggle(type)}
                />
            {/if}
        {/each}
    {/if}
</div>

<style lang="scss">
    .wrapper {
        flex-wrap: wrap;
        :global(.form-switch) {
            margin-right: 1rem;
        }
    }
</style>
