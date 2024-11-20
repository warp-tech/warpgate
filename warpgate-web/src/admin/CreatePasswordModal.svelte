<script lang="ts">
    import {
        Button,
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
    let validationFeedback: string|undefined = $state()
    let passwordValid = $state(false)

    function _create () {
        if (!password) {
            return
        }
        isOpen = false
        create(password)
    }

    function _validate () : boolean {
        passwordValid = password.trim().length > 1

        if (!passwordValid) {
            validationFeedback = 'Password cannot be empty or whitespace'
        } else {
            validationFeedback = undefined
        }

        return passwordValid
    }

    function _cancel () {
        isOpen = false
        password = ''
    }
</script>

<Modal toggle={_cancel} isOpen={isOpen} on:open={() => field?.focus()}>
    <ModalHeader toggle={_cancel}>
        Password
    </ModalHeader>
    <ModalBody>
            <FormGroup floating class="mt-3" label="Enter a new password">
                <Input
                    bind:inner={field}
                    bind:feedback={validationFeedback}
                    type="password"
                    placeholder="New password"
                    valid={passwordValid}
                    invalid={!passwordValid}
                    on:change={_validate}
                    bind:value={password} />
            </FormGroup>
    </ModalBody>
    <ModalFooter>
        <div class="d-flex">
            <Button
                class="ms-auto"
                disabled={!_validate}
                outline
                on:click={_create}
            >Create</Button>

            <Button
                class="ms-2"
                outline
                color="danger"
                on:click={_cancel}
            >Cancel</Button>
        </div>
    </ModalFooter>
</Modal>
