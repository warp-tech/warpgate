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

    import ModalHeader from 'common/ModalHeader.svelte'

    interface Props {
        isOpen: boolean
        create: (password: string) => void
    }

    let {
        isOpen = $bindable(true),
        create,
    }: Props = $props()
    let password = $state('')
    let field: HTMLInputElement|undefined = $state()
    let validated = $state(false)

    function _save () {
        if (!password) {
            return
        }
        isOpen = false
        create(password)
        password = ''
    }

    function _cancel () {
        isOpen = false
        password = ''
    }
</script>

<Modal toggle={_cancel} isOpen={isOpen} on:open={() => field?.focus()}>
    <Form {validated} on:submit={_save}>
        <ModalHeader toggle={_cancel}>
            Password
        </ModalHeader>
        <ModalBody>
            <FormGroup floating class="mt-3" label="Enter a new password">
                <Input
                    bind:inner={field}
                    type="password"
                    placeholder="New password"
                    required
                    bind:value={password} />
            </FormGroup>
        </ModalBody>
        <ModalFooter>
            <div class="d-flex">
                <Button
                    class="ms-auto"
                    outline
                    on:click={() => validated = true}
                >Create</Button>

                <Button
                    class="ms-2"
                    outline
                    color="danger"
                    on:click={_cancel}
                >Cancel</Button>
            </div>
        </ModalFooter>
    </Form>
</Modal>
