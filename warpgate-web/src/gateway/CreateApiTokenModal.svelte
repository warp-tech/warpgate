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

    import ModalHeader from 'common/sveltestrap-s5-ports/ModalHeader.svelte'

    interface Props {
        isOpen: boolean
        create: (label: string, expiry: Date) => void
    }

    function toLocalISO(date: Date): string {
        const pad = (n: number) => n.toString().padStart(2, '0')
        const year = date.getFullYear()
        const month = pad(date.getMonth() + 1)
        const day = pad(date.getDate())
        const hours = pad(date.getHours())
        const minutes = pad(date.getMinutes())
        return `${year}-${month}-${day}T${hours}:${minutes}`
    }

    let {
        isOpen = $bindable(true),
        create,
    }: Props = $props()
    let label = $state('')
    let expiry = $state(toLocalISO(new Date(Date.now() + 1000 * 60 * 60 * 24 * 7)))
    let field: HTMLInputElement|undefined = $state()
    let validated = $state(false)

    function _save () {
        create(label, new Date(expiry))
        _cancel()
    }

    function _cancel () {
        isOpen = false
        label = ''
    }
</script>

<Modal toggle={_cancel} isOpen={isOpen} on:open={() => field?.focus()}>
    <Form {validated} on:submit={e => {
        _save()
        e.preventDefault()
    }}>
        <ModalHeader>
            New API token
        </ModalHeader>
        <ModalBody>
            <FormGroup floating label="Descriptive label">
                <Input
                    bind:inner={field}
                    required
                    bind:value={label} />
            </FormGroup>

            <FormGroup floating label="Expiry" spacing="0">
                <Input
                    type="datetime-local"
                    bind:value={expiry}  />
            </FormGroup>
        </ModalBody>
        <ModalFooter>
            <Button
                color="primary"
                class="modal-button"
                on:click={() => validated = true}
            >Create</Button>

            <Button
                color="danger"
                class="modal-button"
                on:click={_cancel}
            >Cancel</Button>
        </ModalFooter>
    </Form>
</Modal>
