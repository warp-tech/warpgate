<script lang="ts">
    /**
     * Generate an SSH client key — restyled in place.
     *
     * Behaviour preserved: label required, the two key kinds with Ed25519 as
     * the default, and save(label, kind).
     *
     * Like ClientKeyModal, the sveltestrap `on:open` seeding is replaced by
     * seeding at construction — the caller mounts this behind {#if}.
     */
    import { SSHClientKeyKind } from 'admin/lib/api'
    import Button from 'ui/Button.svelte'
    import Input from 'ui/Input.svelte'
    import 'ui/layout.css'
    import Modal from 'ui/Modal.svelte'
    import Select from 'ui/Select.svelte'

    interface Props {
        isOpen: boolean
        save: (label: string, kind: SSHClientKeyKind) => void
    }

    let { isOpen = $bindable(true), save }: Props = $props()

    let label = $state('')
    let kind = $state<SSHClientKeyKind>(SSHClientKeyKind.Ed25519)

    function commit() {
        if (!label) {
            return
        }
        isOpen = false
        save(label, kind)
    }

    function cancel() {
        isOpen = false
    }
</script>

<Modal
    bind:open={isOpen}
    title="Generate a client key"
    size="sm"
    onclose={cancel}
>
    <form
        id="wg-generate-key-form"
        class="wg-field-stack"
        onsubmit={e => {
            e.preventDefault()
            commit()
        }}
    >
        <Input label="Label" required autofocus bind:value={label} />

        <Select
            label="Type"
            bind:value={kind}
            options={[
                { value: SSHClientKeyKind.Ed25519, label: 'Ed25519' },
                { value: SSHClientKeyKind.Rsa, label: 'RSA' },
            ]}
        />
    </form>

    {#snippet footer()}
        <Button onclick={cancel}>Cancel</Button>
        <Button
            variant="primary"
            type="submit"
            form="wg-generate-key-form"
            disabled={!label}
        >
            Save
        </Button>
    {/snippet}
</Modal>
