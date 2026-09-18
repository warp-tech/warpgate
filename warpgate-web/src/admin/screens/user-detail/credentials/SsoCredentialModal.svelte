<script lang="ts">
    /**
     * SSO credential — part of 6c.
     *
     * Serves both create and edit; `instance` being non-null means edit, and
     * the caller writes back into it.
     *
     * The original populated the fields from `instance` in the modal's `open`
     * event. There is no such event here, so the fields are seeded from
     * `instance` directly — which is more reliable: the old version depended
     * on the modal being mounted before the event fired, and left the form
     * blank if it was not.
     *
     * Provider `null` means "any configured provider will do", which is
     * different from an empty selection and is why the option is explicit.
     */

    import type { ExistingSsoCredential } from 'admin/lib/api'
    import Loadable from 'common/Loadable.svelte'
    import { api } from 'gateway/lib/api'
    import { untrack } from 'svelte'
    import 'ui/layout.css'
    import Button from 'ui/Button.svelte'
    import Callout from 'ui/Callout.svelte'
    import Input from 'ui/Input.svelte'
    import Modal from 'ui/Modal.svelte'
    import Select from 'ui/Select.svelte'

    interface Props {
        isOpen: boolean
        instance: ExistingSsoCredential | null
        save: (provider: string | null, email: string) => void
    }

    let { isOpen = $bindable(true), instance, save }: Props = $props()

    // Seeded from the instance rather than from an open event. `untrack` is
    // deliberate: CredentialEditor mounts this behind {#if}, so a fresh
    // component exists per open and the initial read is the correct one.
    let provider: string = $state(untrack(() => instance?.provider ?? ''))
    let email: string = $state(untrack(() => instance?.email ?? ''))

    function commit() {
        if (!email) {
            return
        }
        isOpen = false
        save(provider || null, email)
    }
</script>

<Modal
    bind:open={isOpen}
    title={instance ? 'Edit SSO credential' : 'Add an SSO credential'}
    size="sm"
>
    <div class="wg-field-stack">
        <Input
            label="E-mail"
            type="email"
            required
            mono
            autofocus
            bind:value={email}
            hint="The address the identity provider will assert for this user."
        />

        <Loadable promise={api.getSsoProviders()}>
            {#snippet children(providers)}
                {#if !providers.length}
                    <Callout tone="warning" title="No SSO providers configured">
                        Add one to the Warpgate config file before this
                        credential can be used.
                    </Callout>
                {:else}
                    <Select
                        label="SSO provider"
                        bind:value={provider}
                        options={[
                            { value: '', label: 'Any provider' },
                            ...providers.map(p => ({
                                value: p.name,
                                label: p.label ?? p.name,
                            })),
                        ]}
                        hint="“Any provider” accepts this address from whichever provider asserts it."
                    />
                {/if}
            {/snippet}
        </Loadable>
    </div>

    {#snippet footer()}
        <Button onclick={() => (isOpen = false)}>Cancel</Button>
        <Button variant="primary" disabled={!email} onclick={commit}>
            Save
        </Button>
    {/snippet}
</Modal>

<style>
</style>
