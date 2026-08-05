<script lang="ts">
    import {
        Alert,
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
        userId: string
        save: (label: string, signal: AbortSignal) => Promise<void>
    }
    let { isOpen = $bindable(), userId, save }: Props = $props()

    let label = $state('')
    let busy = $state(false)
    let error: string | null = $state(null)
    let field: HTMLInputElement | undefined = $state()
    let abortController: AbortController | null = $state(null)
    let closing = $state(false)

    async function _save() {
        if (!label.trim() || closing) return
        busy = true
        error = null
        abortController = new AbortController()
        try {
            await save(label.trim(), abortController.signal)
            close()
            label = ''
        } catch (e: unknown) {
            if (
                (e instanceof DOMException && e.name === 'AbortError') ||
                closing
            )
                return
            error = e instanceof Error ? e.message : 'Registration failed'
        } finally {
            busy = false
            abortController = null
        }
    }

    function close() {
        closing = true
        if (abortController) {
            abortController.abort()
            abortController = null
        }
        isOpen = false
        // Reset after the modal transition completes
        setTimeout(() => {
            closing = false
        }, 300)
    }
</script>

<Modal toggle={close} {isOpen} on:open={() => field?.focus()}>
    <Form
        on:submit={e => {
        _save()
        e.preventDefault()
    }}
    >
        <ModalBody>
            <p>Enter a name for this passkey or security key.</p>
            <FormGroup floating label="Name (e.g. YubiKey, MacBook Touch ID)">
                <Input
                    bind:inner={field}
                    bind:value={label}
                    disabled={busy}
                    required
                />
            </FormGroup>
            {#if error}
                <Alert color="danger">{error}</Alert>
            {/if}
        </ModalBody>
        <ModalFooter>
            <Button
                class="modal-button"
                color="primary"
                type="submit"
                disabled={busy || !label.trim()}
            >
                Register
            </Button>
            <Button class="modal-button" color="danger" on:click={close}>
                Cancel
            </Button>
        </ModalFooter>
    </Form>
</Modal>
