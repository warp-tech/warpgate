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

    import type { SSHClientKey } from 'admin/lib/api'
    import SecretRefInput from 'common/SecretRefInput.svelte'

    interface Props {
        isOpen: boolean
        instance?: SSHClientKey
        save: (label: string, secretKey: string, isDefault: boolean) => void
    }

    let { isOpen = $bindable(true), instance, save }: Props = $props()

    let field: HTMLInputElement | undefined = $state()
    let label = $state('')
    let secretKey = $state('')
    let isDefault = $state(false)
    let validated = $state(false)
    let keySource = $state<'paste' | 'reference'>('paste')

    function changeKeySource (source: string) {
        keySource = source === 'reference' ? 'reference' : 'paste'
        secretKey = keySource === 'reference' ? 'vault://' : ''
    }

    function _save() {
        if (!label || (!instance && !secretKey)) {
            return
        }
        isOpen = false
        save(label, secretKey, isDefault)
    }

    function _cancel() {
        isOpen = false
    }
</script>

<Modal
    toggle={_cancel}
    {isOpen}
    on:open={() => {
        label = instance?.label ?? ''
        secretKey = ''
        isDefault = instance?.isDefault ?? false
        keySource = 'paste'
        field?.focus()
    }}
>
    <Form
        {validated}
        on:submit={e => {
            _save()
            e.preventDefault()
        }}
    >
        <ModalBody>
            <FormGroup floating label="Label">
                <Input
                    bind:inner={field}
                    type="text"
                    required
                    bind:value={label}
                />
            </FormGroup>
            {#if !instance}
                <FormGroup floating label="Add a key by">
                    <Input
                        type="select"
                        value={keySource}
                        onchange={(e) => changeKeySource((e.target as HTMLSelectElement).value)}
                    >
                        <option value="paste">Pasting a private key</option>
                        <option value="reference">
                            Referencing a secret in Vault / OpenBao
                        </option>
                    </Input>
                </FormGroup>

                {#if keySource === 'paste'}
                    <FormGroup
                        floating
                        label="Private key (OpenSSH or PKCS#8 PEM, no passphrase)"
                        spacing="0"
                    >
                        <Input
                            style="font-family: monospace; height: 15rem"
                            type="textarea"
                            required
                            placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
                            bind:value={secretKey}
                        />
                    </FormGroup>
                {:else}
                    <div class="mb-3">
                        <SecretRefInput bind:value={secretKey} />
                    </div>
                {/if}
            {/if}
            <Input
                type="switch"
                label="Offer to targets by default if no specific key is selected"
                bind:checked={isDefault}
            />
        </ModalBody>
        <ModalFooter>
            <Button
                type="submit"
                color="primary"
                class="modal-button"
                on:click={() => (validated = true)}
            >
                Save
            </Button>

            <Button class="modal-button" color="danger" on:click={_cancel}>
                Cancel
            </Button>
        </ModalFooter>
    </Form>
</Modal>
