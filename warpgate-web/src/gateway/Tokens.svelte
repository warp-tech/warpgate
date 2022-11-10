<script lang="ts">
    import { api, Token } from 'gateway/lib/api'
    import { Alert, Button, FormGroup, Modal, ModalBody, ModalFooter, ModalHeader } from 'sveltestrap'
    import RelativeDate from 'common/RelativeDate.svelte'
    import CopyButton from 'common/CopyButton.svelte'

    let error: Error|undefined
    let tokens: Token[]|undefined
    let newSecret: string|undefined
    let isCreateModalOpen = false
    let newTokenName = ''

    async function load () {
        tokens = await api.getTokens()
    }

    function showCreateTokenModal () {
        isCreateModalOpen = true
        newTokenName = ''
    }

    async function createNewToken () {
        const response = await api.createToken({ createTokenRequest: { name: newTokenName } })
        tokens = [...tokens!, response.token]
        newSecret = response.secret
        isCreateModalOpen = false
    }

    load().catch(e => {
        error = e
    })

    async function deleteToken (token: Token) {
        newSecret = undefined
        await api.deleteToken(token)
        load()
    }
</script>

{#if error}
<Alert color="danger">{error}</Alert>
{/if}

{#if tokens}
    <div class="page-summary-bar">
        <h1>API tokens</h1>
        <button
            class="btn btn-outline-secondary ms-auto"
            on:click={showCreateTokenModal}>
            Create
        </button>
    </div>

    {#if newSecret}
        <FormGroup floating label="New token" class="d-flex align-items-center">
            <input type="text" class="form-control" readonly value={newSecret} />
            <CopyButton text={newSecret} />
        </FormGroup>

        <Alert color="warning" fade={false}>
            The API token is only shown once - you won't be able to see it again.
        </Alert>
    {/if}

    {#if tokens.length }
        <div class="list-group list-group-flush">
            {#each tokens as token}
                <div class="list-group-item">
                    <strong class="me-auto">
                        {token.name}
                    </strong>
                    <small class="text-muted me-4">
                        <RelativeDate date={token.created} />
                    </small>
                    <a href={''} on:click|preventDefault={() => deleteToken(token)}>Delete</a>
                </div>
            {/each}
        </div>
    {:else}
        <Alert color="info" fade={false}>
            Tokens grant access to the Warpgate API.
        </Alert>
    {/if}
{/if}


<Modal bind:isOpen={isCreateModalOpen}>
    <ModalHeader toggle={() => isCreateModalOpen = false}>
        Create API token
    </ModalHeader>
    <ModalBody>
        <form on:submit|preventDefault={createNewToken}>
            <FormGroup floating label="Name" class="d-flex align-items-center">
                <!-- svelte-ignore a11y-autofocus -->
                <input
                    type="text"
                    class="form-control"
                    bind:value={newTokenName}
                    autofocus
                />
            </FormGroup>
        </form>
    </ModalBody>
    <ModalFooter>
        <div class="d-flex">
            <Button
                class="ms-auto"
                outline
                disabled={!newTokenName}
                on:click={createNewToken}
            >Save</Button>

            <Button
                class="ms-2"
                outline
                color="danger"
                on:click={() => isCreateModalOpen = false}
            >Cancel</Button>
        </div>
    </ModalFooter>
</Modal>

<style lang="scss">
    .list-group-item {
        display: flex;
        align-items: center;
    }
</style>
