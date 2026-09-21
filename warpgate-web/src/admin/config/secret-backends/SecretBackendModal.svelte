<script lang="ts">
    import {
        Button,
        Form,
        FormGroup,
        Input,
        Modal,
        ModalBody,
        ModalFooter,
    } from '@sveltestrap/sveltestrap'
    import type {
        BackendType,
        SecretBackendAuth,
        SecretBackendRequest,
        SecretBackend,
    } from 'admin/lib/api'

    interface Props {
        isOpen: boolean
        instance?: SecretBackend
        save: (request: SecretBackendRequest) => void
    }

    let { isOpen = $bindable(true), instance, save }: Props = $props()

    let validated = $state(false)

    let name = $state('')
    let backendType: BackendType = $state('vault')
    let address = $state('')
    let namespace = $state('')
    let method: SecretBackendAuth['method'] = $state('Token')
    let mount = $state('')
    let token = $state('')
    let roleId = $state('')
    let secretId = $state('')
    let kubernetesRole = $state('')
    let tlsSkipVerify = $state(false)
    let allowedPaths = $state('')

    // Secrets are write-only: blank on edit keeps the stored value, which only
    // exists for the method the backend was saved with.
    const secretStored = $derived(instance?.auth.method === method)
    const secretPlaceholder = $derived(secretStored ? 'Unchanged' : '')

    function reset() {
        const auth = instance?.auth
        name = instance?.name ?? ''
        backendType = instance?.backendType ?? 'vault'
        address = instance?.address ?? ''
        namespace = instance?.namespace ?? ''
        method = auth?.method ?? 'Token'
        mount = (auth?.method === 'Token' ? undefined : auth?.mount) ?? ''
        token = ''
        roleId = auth?.method === 'AppRole' ? auth.roleId : ''
        secretId = ''
        kubernetesRole = auth?.method === 'Kubernetes' ? auth.role : ''
        tlsSkipVerify = instance?.tlsSkipVerify ?? false
        allowedPaths = instance?.allowedPaths.join('\n') ?? ''
    }

    function auth(): SecretBackendAuth {
        if (method === 'AppRole') {
            return { method, roleId, secretId, mount: mount || undefined }
        }
        if (method === 'Kubernetes') {
            return { method, role: kubernetesRole, mount: mount || undefined }
        }
        return { method: 'Token', token }
    }

    // Native validation gates submit, so this only runs with a valid form.
    function _save() {
        isOpen = false
        save({
            name,
            backendType,
            address,
            namespace: namespace || undefined,
            auth: auth(),
            tlsSkipVerify,
            allowedPaths: allowedPaths.split('\n').map(p => p.trim()).filter(p => p),
        })
    }

    function _cancel() {
        isOpen = false
    }
</script>

<Modal toggle={_cancel} {isOpen} on:open={reset}>
    <Form
        {validated}
        on:submit={e => {
            _save()
            e.preventDefault()
        }}
    >
        <ModalBody>
            <FormGroup floating label="Name">
                <Input type="text" required pattern="[A-Za-z0-9._\-]+" maxlength={64} bind:value={name} />
            </FormGroup>
            <FormGroup floating label="Type">
                <Input type="select" bind:value={backendType}>
                    <option value="vault">Vault</option>
                    <option value="openbao">OpenBao</option>
                </Input>
            </FormGroup>
            <FormGroup floating label="Address">
                <Input type="url" required placeholder="https://vault.example.com:8200" bind:value={address} />
            </FormGroup>
            <FormGroup floating label="Namespace (optional)">
                <Input type="text" bind:value={namespace} />
            </FormGroup>

            <FormGroup floating label="Authentication">
                <Input type="select" bind:value={method}>
                    <option value="Token">Token</option>
                    <option value="AppRole">AppRole</option>
                    <option value="Kubernetes">Kubernetes</option>
                </Input>
            </FormGroup>
            {#if method === 'Token'}
                <FormGroup floating label="Token">
                    <Input type="password" autocomplete="off" required={!secretStored} placeholder={secretPlaceholder} bind:value={token} />
                </FormGroup>
            {:else if method === 'AppRole'}
                <FormGroup floating label="Role ID">
                    <Input type="text" required bind:value={roleId} />
                </FormGroup>
                <FormGroup floating label="Secret ID">
                    <Input type="password" autocomplete="off" required={!secretStored} placeholder={secretPlaceholder} bind:value={secretId} />
                </FormGroup>
                <FormGroup floating label="Auth mount (default: approle)">
                    <Input type="text" bind:value={mount} />
                </FormGroup>
            {:else}
                <FormGroup floating label="Role">
                    <Input type="text" required bind:value={kubernetesRole} />
                </FormGroup>
                <FormGroup floating label="Auth mount (default: kubernetes)">
                    <Input type="text" bind:value={mount} />
                </FormGroup>
            {/if}

            <FormGroup floating label="Allowed KV path prefixes, one per line (empty: any)">
                <Input type="textarea" style="height: 5rem" bind:value={allowedPaths} />
            </FormGroup>
            <Input type="switch" label="Skip TLS certificate verification" bind:checked={tlsSkipVerify} />
        </ModalBody>
        <ModalFooter>
            <Button type="submit" color="primary" class="modal-button" on:click={() => (validated = true)}>
                Save
            </Button>
            <Button class="modal-button" color="danger" on:click={_cancel}>Cancel</Button>
        </ModalFooter>
    </Form>
</Modal>
