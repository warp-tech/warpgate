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

    interface Props {
        isOpen: boolean
        title?: string
        message: string
        confirmText?: string
        confirm: () => void
    }

    let {
        isOpen = $bindable(true),
        title = 'Confirm deletion',
        message,
        confirmText = 'YES',
        confirm,
    }: Props = $props()

    let field: HTMLInputElement | undefined = $state()
    let typedValue = $state('')
    let validated = $state(false)

    let isConfirmed = $derived(typedValue === confirmText)

    function _confirm() {
        if (!isConfirmed) {
            return
        }
        isOpen = false
        confirm()
    }

    function _cancel() {
        isOpen = false
    }
</script>

<Modal
    toggle={_cancel}
    {isOpen}
    on:open={() => {
        typedValue = ''
        validated = false
        field?.focus()
    }}
>
    <Form
        {validated}
        on:submit={e => {
            _confirm()
            e.preventDefault()
        }}
    >
        <ModalBody>
            <p>{title}</p>
            <p>{message}</p>
            <FormGroup floating label={`Type "${confirmText}" to confirm`}>
                <Input
                    bind:inner={field}
                    type="text"
                    required
                    pattern={confirmText}
                    autocomplete="off"
                    bind:value={typedValue}
                />
            </FormGroup>
        </ModalBody>
        <ModalFooter>
            <Button
                type="submit"
                color="danger"
                class="modal-button"
                disabled={!isConfirmed}
                on:click={() => (validated = true)}
            >
                Delete
            </Button>

            <Button class="modal-button" color="secondary" on:click={_cancel}>
                Cancel
            </Button>
        </ModalFooter>
    </Form>
</Modal>
