<script lang="ts">
    import { faCopy } from '@fortawesome/free-solid-svg-icons'
    import {
        Alert,
        Button,
        FormGroup,
        Input,
        Modal,
        ModalBody,
        ModalFooter,
        ModalHeader,
    } from '@sveltestrap/sveltestrap'
    import { api, type ScimTokenResponse } from 'admin/lib/api'
    import { adminPermissions } from 'admin/lib/store'
    import AsyncButton from 'common/AsyncButton.svelte'
    import EmptyState from 'common/EmptyState.svelte'
    import { stringifyError } from 'common/errors'
    import InfoBox from 'common/InfoBox.svelte'
    import ItemList, { type PaginatedResponse } from 'common/ItemList.svelte'
    import RelativeDate from 'common/RelativeDate.svelte'
    import copyTextToClipboard from 'copy-text-to-clipboard'
    import { api as gatewayApi } from 'gateway/lib/api'
    import { from, map, type Observable } from 'rxjs'
    import { onMount } from 'svelte'
    import Fa from 'svelte-fa'

    const baseUrl = `${location.origin}/@warpgate/scim/v2`

    let error = $state<string | null>(null)
    let gen = $state(0)
    let ssoProviders = $state<string[]>([])

    // Create form
    let createOpen = $state(false)
    let label = $state('')
    let ssoProvider = $state('')
    let expiry = $state('')

    // The secret, shown once
    let created = $state<{ label: string; secret: string } | null>(null)
    let copied = $state(false)

    // Creating a token takes every permission the token itself grants
    const canCreate = $derived(
        $adminPermissions.configEdit &&
            $adminPermissions.usersDelete &&
            $adminPermissions.accessRolesDelete,
    )

    onMount(async () => {
        try {
            ssoProviders = (await gatewayApi.getSsoProviders()).map(p => p.name)
        } catch {
            ssoProviders = []
        }
    })

    function load(): Observable<PaginatedResponse<ScimTokenResponse>> {
        return from(api.getScimTokens()).pipe(
            map(items => ({
                items,
                offset: 0,
                total: items.length,
            })),
        )
    }

    function openCreate() {
        label = ''
        ssoProvider = ''
        expiry = ''
        error = null
        createOpen = true
    }

    async function create() {
        error = null
        try {
            const result = await api.createScimToken({
                createScimTokenRequest: {
                    label,
                    ssoProvider: ssoProvider || undefined,
                    expiry: expiry ? new Date(expiry) : undefined,
                },
            })
            createOpen = false
            copied = false
            created = { label: result.token.label, secret: result.secret }
            gen++
        } catch (e) {
            error = await stringifyError(e)
        }
    }

    async function remove(token: ScimTokenResponse) {
        if (
            !confirm(
                `Delete the SCIM token "${token.label}"? The identity provider using it will stop syncing.`,
            )
        ) {
            return
        }
        error = null
        try {
            await api.deleteScimToken({ id: token.id })
            gen++
        } catch (e) {
            error = await stringifyError(e)
        }
    }

    function copySecret() {
        if (created) {
            copyTextToClipboard(created.secret)
            copied = true
        }
    }
</script>

<div class="container-max-md">
    <div class="page-summary-bar">
        <h1>SCIM provisioning</h1>
        {#if $adminPermissions.configEdit}
            <Button
                class="ms-auto"
                color="primary"
                disabled={!canCreate}
                title={canCreate
                    ? ''
                    : 'Requires the users delete and access roles delete permissions'}
                onclick={openCreate}
            >
                Create a token
            </Button>
        {/if}
    </div>

    <InfoBox>
        Identity providers (Okta, Entra ID, …) can create, disable and delete
        users and manage access-role membership over SCIM 2.0. SCIM groups map
        to access roles: a group pushed from the provider links to the role of
        the same name, and deleting the group there deletes the role, including
        its target assignments.
        <div class="mt-2">Tenant URL: <code>{baseUrl}</code></div>
    </InfoBox>

    {#if error}
        <Alert color="danger">{error}</Alert>
    {/if}

    {#if created}
        <Alert color="success" class="d-flex flex-column gap-2">
            <div>
                Token <strong>{created.label}</strong> created. Copy the secret
                now: it will not be shown again.
            </div>
            <div class="d-flex align-items-center gap-2">
                <code class="text-break">{created.secret}</code>
                <Button size="sm" color="secondary" onclick={copySecret}>
                    <Fa icon={faCopy} fw />
                    {copied ? 'Copied' : 'Copy'}
                </Button>
            </div>
        </Alert>
    {/if}

    {#if $adminPermissions.configEdit}
        {#key gen}
            <ItemList {load} showSearch={false}>
                {#snippet empty()}
                    <EmptyState
                        title="No SCIM tokens"
                        hint="Create a token and configure it in your identity provider's SCIM integration"
                    />
                {/snippet}
                {#snippet item(token)}
                    <div class="list-group-item px-0">
                        <div class="d-flex align-items-center gap-3">
                            <div class="flex-grow-1">
                                <strong>{token.label}</strong>
                                <small class="d-block text-muted">
                                    {#if token.ssoProvider}
                                        Links users to the
                                        <strong>{token.ssoProvider}</strong>
                                        SSO provider &bull;
                                    {/if}
                                    Created
                                    <RelativeDate date={token.created} />
                                    {#if token.lastUsed}
                                        &bull; Last used
                                        <RelativeDate date={token.lastUsed} />
                                    {:else}
                                        &bull; Never used
                                    {/if}
                                    {#if token.expiry}
                                        &bull; Expires
                                        <RelativeDate date={token.expiry} />
                                    {/if}
                                </small>
                            </div>
                            <Button
                                color="link px-0"
                                class="text-danger"
                                onclick={() => remove(token)}
                            >
                                Delete
                            </Button>
                        </div>
                    </div>
                {/snippet}
            </ItemList>
        {/key}
    {:else}
        <Alert color="warning">
            You have no permission to manage SCIM tokens.
        </Alert>
    {/if}
</div>

<Modal isOpen={createOpen} toggle={() => (createOpen = false)}>
    <ModalHeader toggle={() => (createOpen = false)}>
        Create a SCIM token
    </ModalHeader>
    <ModalBody>
        <FormGroup floating label="Label">
            <Input bind:value={label} placeholder="e.g. Okta" />
        </FormGroup>
        <FormGroup floating label="SSO provider (optional)">
            <Input type="select" bind:value={ssoProvider}>
                <option value="">None</option>
                {#each ssoProviders as name (name)}
                    <option value={name}>{name}</option>
                {/each}
            </Input>
            <small class="text-muted">
                Keeps an SSO credential for this provider in step with each
                provisioned user's primary email, so they can log in through it
                right away.
            </small>
        </FormGroup>
        <FormGroup floating label="Expiry (optional)">
            <Input type="datetime-local" bind:value={expiry} />
        </FormGroup>
    </ModalBody>
    <ModalFooter>
        <AsyncButton color="primary" disabled={!label.trim()} click={create}>
            Create
        </AsyncButton>
        <Button color="secondary" onclick={() => (createOpen = false)}>
            Cancel
        </Button>
    </ModalFooter>
</Modal>
