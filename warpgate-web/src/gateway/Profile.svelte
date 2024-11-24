<script lang="ts">
    import { api, CredentialKind, PasswordState, type CredentialsState, type ExistingPublicKeyCredential } from 'gateway/lib/api'

    import { serverInfo } from 'gateway/lib/store'
    import DelayedSpinner from 'common/DelayedSpinner.svelte'
    import Alert from 'common/Alert.svelte'
    import { stringifyError } from 'common/errors'
    import { faKey } from '@fortawesome/free-solid-svg-icons'
    import Fa from 'svelte-fa'
    import PublicKeyCredentialModal from 'admin/PublicKeyCredentialModal.svelte'
    import { Button } from '@sveltestrap/sveltestrap'

    let error: string|null = $state(null)
    let creds: CredentialsState | undefined = $state()

    let creatingPublicKeyCredential = $state(false)

    async function load () {
        try {
            creds = await api.getMyCredentials()
        } catch (err) {
            error = await stringifyError(err)
        }
    }

    async function createPublicKeyCredential (opensshPublicKey: string) {
        const credential = await api.addMyPublicKey({
            newPublicKeyCredential: {
                opensshPublicKey,
            },
        })
        creds!.publicKeys.push(credential)
    }

    async function deletePublicKey (credential: ExistingPublicKeyCredential) {
        creds!.publicKeys = creds!.publicKeys.filter(c => c.id !== credential.id)
        await api.deleteMyPublicKey(credential)
    }
</script>

<div class="page-summary-bar">
    <div>
        <h1>{$serverInfo!.username}</h1>
        <div class="text-muted">User</div>
    </div>
</div>


{#await load()}
<DelayedSpinner />
{:then}
{#if creds}

    <h3>Password</h3>
    {#if creds.password === PasswordState.Unset}
    No pw
    {/if}
    {#if creds.password === PasswordState.MultipleSet}
    Multiple pw
    {/if}
    {#if creds.password === PasswordState.Set}
    Pw present
    {/if}

    <h3>OTP</h3>
    {#each creds.otp as cred}
    OTP cred {cred.id}
    {/each}


    <div class="d-flex align-items-center mt-4 mb-2">
        <h4 class="m-0">Public keys</h4>
        <span class="ms-auto"></span>
        <Button size="sm" color="link" on:click={() => {
            creatingPublicKeyCredential = true
        }}>Add new</Button>
    </div>

    <div class="list-group list-group-flush mb-3">
        {#each creds.publicKeys as credential}
        <div class="list-group-item credential">
            <Fa fw icon={faKey} />
            <span class="type">{credential.label}</span>
            <span class="ms-auto"></span>
            <a
                class="ms-2"
                href={''}
                onclick={e => {
                    deletePublicKey(credential)
                    e.preventDefault()
                }}>
                Delete
            </a>
        </div>
        {/each}
    </div>

    {#if creds.publicKeys.length === 0 && creds.credentialPolicy.ssh?.includes(CredentialKind.PublicKey)}
        <Alert color="warning">
            Your credential policy requires using a public key for authentication. Without one, you won't be able to log in.
        </Alert>
    {/if}


    {#each creds.publicKeys as cred}
    PK cred {cred.label}
    {/each}

    <h3>SSO</h3>
    {#each creds.sso as cred}
    SSO cred {cred.email}
    {/each}


{/if}
{/await}

{#if error}
<Alert color="danger">{error}</Alert>
{/if}


{#if creatingPublicKeyCredential}
<PublicKeyCredentialModal
    bind:isOpen={creatingPublicKeyCredential}
    save={createPublicKeyCredential}
/>
{/if}
<!--
<div class="d-flex">
    <AsyncButton
        class="ms-auto"
        outline
        click={update}
    >Save</AsyncButton>
</div> -->

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
