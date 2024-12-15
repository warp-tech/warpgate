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
    import { type ExistingPublicKeyCredential } from './lib/api'

    interface Props {
        isOpen: boolean
        instance?: ExistingPublicKeyCredential
        save: (label: string, opensshPublicKey: string) => void
    }

    let {
        isOpen = $bindable(true),
        instance,
        save,
    }: Props = $props()

    let field: HTMLInputElement|undefined = $state()
    let label: string = $state('')
    let opensshPublicKey: string = $state('')
    let validated = $state(false)

    function _save () {
        if (!opensshPublicKey || !label) {
            return
        }
        if (opensshPublicKey.includes(' ')) {
            const parts = opensshPublicKey.split(' ').filter(x => x)
            opensshPublicKey = `${parts[0]} ${parts[1]}`
        }
        isOpen = false
        save(label, opensshPublicKey)
    }

    function _cancel () {
        isOpen = false
    }
</script>

<Modal toggle={_cancel} isOpen={isOpen} on:open={() => {
    if (instance) {
        label = instance.label
        opensshPublicKey = instance.opensshPublicKey
    }
    field?.focus()
}}>
    <Form {validated} on:submit={e => {
        _save()
        e.preventDefault()
    }}>
        <ModalHeader toggle={_cancel}>
            Add an SSH public key
        </ModalHeader>
        <ModalBody>
            <FormGroup floating label="Label">
                <Input
                    bind:inner={field}
                    type="text"
                    required
                    bind:value={label} />
            </FormGroup>
            <FormGroup floating label="Public key in OpenSSH format">
                <Input
                    style="font-family: monospace; height: 15rem"
                    bind:inner={field}
                    type="textarea"
                    required
                    placeholder="ssh-XXX YYYYYY"
                    bind:value={opensshPublicKey} />
            </FormGroup>
        </ModalBody>
        <ModalFooter>
            <div class="d-flex">
                <Button
                    type="submit"
                    class="ms-auto"
                    outline
                    on:click={() => validated = true}
                >Save</Button>

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
