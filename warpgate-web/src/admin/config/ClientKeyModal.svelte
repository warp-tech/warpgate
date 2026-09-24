<script lang="ts">
    /**
     * Import or edit an SSH client key — restyled in place.
     *
     * Behaviour preserved: label required always, the private key required
     * only when creating (editing keeps the stored one), the default-key
     * switch, and save(label, secretKey, isDefault).
     *
     * The original seeded its fields in sveltestrap's `on:open` event. ui/Modal
     * has no such event, and there is a better answer available here: the
     * caller mounts this behind {#if}, so a fresh component exists per open and
     * the fields can seed from `instance` at construction. That also fixes the
     * case where the modal was already mounted and the event never fired,
     * leaving the form showing the previous key's label.
     */
    import type { SSHClientKey } from 'admin/lib/api'
    import { untrack } from 'svelte'
    import Button from 'ui/Button.svelte'
    import Input from 'ui/Input.svelte'
    import 'ui/layout.css'
    import Modal from 'ui/Modal.svelte'
    import Textarea from 'ui/Textarea.svelte'
    import Toggle from 'ui/Toggle.svelte'

    interface Props {
        isOpen: boolean
        instance?: SSHClientKey
        save: (label: string, secretKey: string, isDefault: boolean) => void
    }

    let { isOpen = $bindable(true), instance, save }: Props = $props()

    // Seeded once: mounted behind {#if}, so a fresh component exists per open.
    let label = $state(untrack(() => instance?.label ?? ''))
    let secretKey = $state('')
    let isDefault = $state(untrack(() => instance?.isDefault ?? false))

    const ready = $derived(!!label && (!!instance || !!secretKey))

    function commit() {
        if (!ready) {
            return
        }
        isOpen = false
        save(label, secretKey, isDefault)
    }

    function cancel() {
        isOpen = false
    }
</script>

<Modal
    bind:open={isOpen}
    title={instance ? 'Edit client key' : 'Import a client key'}
    size="md"
    onclose={cancel}
>
    <form
        id="wg-client-key-form"
        class="wg-field-stack"
        onsubmit={e => {
            e.preventDefault()
            commit()
        }}
    >
        <Input label="Label" required autofocus bind:value={label} />

        {#if !instance}
            <Textarea
                label="Private key (OpenSSH or PKCS#8 PEM, no passphrase)"
                rows={10}
                required
                placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
                bind:value={secretKey}
            />
        {/if}

        <Toggle
            label="Offer to targets by default if no specific key is selected"
            bind:checked={isDefault}
        />
    </form>

    {#snippet footer()}
        <Button onclick={cancel}>Cancel</Button>
        <Button
            variant="primary"
            type="submit"
            form="wg-client-key-form"
            disabled={!ready}
        >
            Save
        </Button>
    {/snippet}
</Modal>
