<script lang="ts">
    import { faIdBadge, faKey, faKeyboard, faMobileScreen } from '@fortawesome/free-solid-svg-icons'
    import { CredentialKind, type UserAuthCredential, type UserRequireCredentialsPolicy } from 'admin/lib/api'
    import Fa from 'svelte-fa'
    import { Button } from '@sveltestrap/sveltestrap'
    import UserCredentialModal from './UserCredentialModal.svelte'
    import { possibleCredentials } from 'common/protocols'

    interface Props {
        value: UserAuthCredential[];
        username: string,
        credentialPolicy?: UserRequireCredentialsPolicy,
    }

    let { value = $bindable(), username, credentialPolicy = $bindable() }: Props = $props()

    let editingCredential: UserAuthCredential|undefined = $state()


    function abbreviatePublicKey (key: string) {
        return key.slice(0, 16) + '...' + key.slice(-8)
    }

    function saveCredential () {
        if (!editingCredential) {
            return
        }
        if (value.includes(editingCredential)) {
            value = [...value]
        } else {
            value.push(editingCredential)

            if (credentialPolicy) {
                for (const protocol of ['http', 'ssh'] as ('http'|'ssh')[]) {
                    for (const ck of [CredentialKind.Password, CredentialKind.PublicKey]) {
                        if (
                            editingCredential.kind === CredentialKind.Totp
                        && !credentialPolicy[protocol]
                        && value.some(x => x.kind === ck)
                        && possibleCredentials[protocol]?.has(ck)
                        ) {
                            credentialPolicy = {
                                ...credentialPolicy,
                                [protocol]: [ck, CredentialKind.Totp],
                            }
                        }
                    }
                }
            }
        }
        editingCredential = undefined
    }

    function deleteCredential (credential: UserAuthCredential) {
        value = value.filter(c => c !== credential)
    }
</script>

<div class="d-flex align-items-center mt-4 mb-2">
    <h4 class="m-0">Credentials</h4>
    <span class="ms-auto"></span>
    <Button size="sm" color="link" on:click={() => editingCredential = {
        kind: 'Password',
        hash: '',
    }}>Add password</Button>
    <Button size="sm" color="link" on:click={() => editingCredential = {
        kind: 'PublicKey',
        key: '',
    }}>Add public key</Button>
    <Button size="sm" color="link" on:click={() => editingCredential = {
        kind: 'Totp',
        key: [],
    }}>Add OTP</Button>
    <Button size="sm" color="link" on:click={() => editingCredential = {
        kind: 'Sso',
        email: '',
    }}>Add SSO</Button>
</div>

<div class="list-group list-group-flush mb-3">
    {#each value as credential}
    <div class="list-group-item credential">
        {#if credential.kind === 'Password'}
        <Fa fw icon={faKeyboard} />
        <span class="type">Password</span>
        {/if}
        {#if credential.kind === 'PublicKey'}
        <Fa fw icon={faKey} />
        <span class="type">Public key</span>
        <span class="text-muted ms-2">{abbreviatePublicKey(credential.key)}</span>
        {/if}
        {#if credential.kind === 'Totp'}
        <Fa fw icon={faMobileScreen} />
        <span class="type">One-time password</span>
        {/if}
        {#if credential.kind === 'Sso'}
        <Fa fw icon={faIdBadge} />
        <span class="type">Single sign-on</span>
        <span class="text-muted ms-2">
            {credential.email}
            {#if credential.provider} ({credential.provider}){/if}
        </span>
        {/if}

        <span class="ms-auto"></span>
        <a
            class="ms-2"
            href={''}
            onclick={e => {
                editingCredential = credential
                e.preventDefault()
            }}>
            Change
        </a>
    <a
        class="ms-2"
        href={''}
        onclick={e => {
            deleteCredential(credential)
            e.preventDefault()
        }}>
        Delete
    </a>
</div>
{/each}
</div>

{#if editingCredential}
<UserCredentialModal
    credential={editingCredential}
    username={username}
    save={saveCredential}
    cancel={() => editingCredential = undefined}
/>
{/if}

<style lang="scss">
    .credential {
        display: flex;
        align-items: center;

        .type {
            margin-left: .5rem;
        }

        a {
            display: none;
        }

        &:hover a {
            display: initial;
        }
    }
</style>
