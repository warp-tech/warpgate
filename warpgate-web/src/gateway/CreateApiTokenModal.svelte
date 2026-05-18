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
        maxDurationSeconds?: number | null
    }

    let {
        isOpen = $bindable(true),
        create,
        maxDurationSeconds = null,
    }: Props = $props()
    let label = $state('')

    const defaultDurationMs = maxDurationSeconds
        ? Math.min(maxDurationSeconds * 1000, 1000 * 60 * 60 * 24 * 7)
        : 1000 * 60 * 60 * 24 * 7

    let expiry = $state(new Date(Date.now() + defaultDurationMs).toISOString())
    let maxExpiry = $derived(maxDurationSeconds
        ? new Date(Date.now() + maxDurationSeconds * 1000).toISOString().slice(0, 16)
        : undefined)
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
                    max={maxExpiry}
                    bind:value={expiry}  />
                {#if maxDurationSeconds}
                    <small class="text-muted">
                        Maximum: {Math.floor(maxDurationSeconds / 86400)} days
                    </small>
                {/if}
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
