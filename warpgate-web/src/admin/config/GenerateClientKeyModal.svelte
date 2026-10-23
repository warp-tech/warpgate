<script lang="ts">
    import {
        Button,
        Form,
        FormGroup,
        Input,
        Modal,
        ModalBody,
        ModalFooter,
        ModalHeader,
    } from '@sveltestrap/sveltestrap'

    import { SSHClientKeyKind } from 'admin/lib/api'

    interface Props {
        isOpen: boolean
        save: (label: string, kind: SSHClientKeyKind) => void
    }

    let { isOpen = $bindable(true), save }: Props = $props()

    let field: HTMLInputElement | undefined = $state()
    let label = $state('')
    let kind = $state<SSHClientKeyKind>(SSHClientKeyKind.Ed25519)
    let validated = $state(false)

    function _save() {
        if (!label) {
            return
        }
        isOpen = false
        save(label, kind)
    }

    function _cancel() {
        isOpen = false
    }
</script>

<Modal
    toggle={_cancel}
    {isOpen}
    on:open={() => {
        label = ''
        kind = SSHClientKeyKind.Ed25519
        field?.focus()
    }}
>
    <ModalHeader>Generate a client key</ModalHeader>
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
            <FormGroup floating label="Type">
                <Input type="select" bind:value={kind}>
                    <option value={SSHClientKeyKind.Ed25519}>Ed25519</option>
                    <option value={SSHClientKeyKind.Rsa}>RSA</option>
                </Input>
            </FormGroup>
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

            <Button class="modal-button" color="secondary" on:click={_cancel}>
                Cancel
            </Button>
        </ModalFooter>
    </Form>
</Modal>
