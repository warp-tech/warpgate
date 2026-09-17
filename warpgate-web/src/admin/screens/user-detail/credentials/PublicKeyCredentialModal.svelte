<script lang="ts">
    /**
     * SSH public key credential — part of 6c.
     *
     * Behaviour preserved:
     *   - pasting a key auto-fills the label from the key's trailing comment,
     *     but only when the label is still empty, so it never overwrites a
     *     name the operator typed
     *   - the key is normalised to "type base64" on save, discarding the
     *     comment and any trailing whitespace, because the comment is not part
     *     of the credential and would otherwise vary between two records of
     *     the same key
     *
     * Bug fixed while migrating: the original bound `bind:inner={field}` to
     * both the label input and the textarea, so `field` always ended up
     * pointing at the textarea. Focus-on-open therefore landed on the key box
     * rather than the label. Each element now has its own reference and the
     * label takes focus, which is the first thing to fill in.
     */

    import type { ExistingPublicKeyCredential } from 'admin/lib/api'
    import { untrack } from 'svelte'
    import 'ui/forms.css'
    import Button from 'ui/Button.svelte'
    import Input from 'ui/Input.svelte'
    import Modal from 'ui/Modal.svelte'
    import Textarea from 'ui/Textarea.svelte'

    interface Props {
        isOpen: boolean
        instance?: ExistingPublicKeyCredential
        save: (label: string, opensshPublicKey: string) => void
    }

    let { isOpen = $bindable(true), instance, save }: Props = $props()

    // `untrack`: mounted behind {#if}, so a fresh component exists per open
    // and the initial read is the correct one.
    let label: string = $state(untrack(() => instance?.label ?? ''))
    let opensshPublicKey: string = $state(
        untrack(() => instance?.opensshPublicKey ?? ''),
    )

    const PK_REGEX = /^ssh-([\w-]+) [A-Za-z0-9+/=]+( (?<comment>[^ ]+))?$/

    function onPublicKeyPaste(event: ClipboardEvent) {
        const pasted = event.clipboardData?.getData('text') ?? ''
        const match = PK_REGEX.exec(pasted.trim())
        // Only when empty: never overwrite a name the operator typed.
        if (!label && match) {
            label = match.groups?.comment || ''
        }
    }

    function commit() {
        if (!opensshPublicKey || !label) {
            return
        }
        // Normalise to "type base64" — the comment is not part of the
        // credential and would otherwise differ between two copies of one key.
        let key = opensshPublicKey.trim()
        if (key.includes(' ')) {
            const parts = key.split(' ').filter(Boolean)
            key = `${parts[0]} ${parts[1]}`
        }
        isOpen = false
        save(label, key)
    }
</script>

<Modal
    bind:open={isOpen}
    title={instance ? 'Edit public key' : 'Add a public key'}
    size="md"
>
    <div class="wg-field-stack">
        <Input
            label="Label"
            required
            autofocus
            bind:value={label}
            hint="Filled in from the key's comment when you paste one."
        />

        <Textarea
            label="Public key in OpenSSH format"
            id="openssh-key"
            rows={8}
            required
            placeholder="ssh-ed25519 AAAA… user@host"
            bind:value={opensshPublicKey}
            onpaste={onPublicKeyPaste}
        />
    </div>

    {#snippet footer()}
        <Button onclick={() => (isOpen = false)}>Cancel</Button>
        <Button
            variant="primary"
            disabled={!label || !opensshPublicKey}
            onclick={commit}
        >
            Save
        </Button>
    {/snippet}
</Modal>
