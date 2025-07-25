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

    import { type ExistingSsoCredential } from './lib/api'
    import { api } from 'gateway/lib/api'
    import Alert from 'common/sveltestrap-s5-ports/Alert.svelte'
    import Loadable from 'common/Loadable.svelte'

    interface Props {
        isOpen: boolean
        instance: ExistingSsoCredential|null
        save: (provider: string|null, email: string) => void
    }

    let {
        isOpen = $bindable(true),
        instance,
        save,
    }: Props = $props()

    let provider: string|null = $state(null)
    let email: string = $state('')
    let validated = $state(false)

    function _save () {
        if (!email) {
            return
        }
        isOpen = false
        save(provider, email)
    }

    function _cancel () {
        isOpen = false
    }
</script>

<Modal toggle={_cancel} isOpen={isOpen} on:open={() => {
    if (instance) {
        provider = instance.provider ?? null
        email = instance.email
    }
}}>
    <Form {validated} on:submit={e => {
        _save()
        e.preventDefault()
    }}>
        <ModalBody>
            <FormGroup floating label="E-mail">
                <Input
                    type="email"
                    required
                    bind:value={email} />
            </FormGroup>

            <Loadable promise={api.getSsoProviders()}>
                {#snippet children(providers)}
                    {#if !providers.length}
                    <Alert color="warning">
                        You don't have any SSO providers configured. Add them to your config file first.
                    </Alert>
                    {/if}
                    <FormGroup floating label="SSO provider" spacing="0">
                        <Input
                            bind:value={provider}
                            type="select"
                        >
                            <option value={null} selected>Any</option>
                            {#each providers as provider (provider.name)}
                            <option value={provider.name}>{provider.label ?? provider.name}</option>
                            {/each}
                        </Input>
                    </FormGroup>
                {/snippet}
            </Loadable>
        </ModalBody>
        <ModalFooter>
            <Button
                type="submit"
                color="primary"
                class="modal-button"
                on:click={() => validated = true}
            >Save</Button>

            <Button
                class="modal-button"
                color="danger"
                on:click={_cancel}
            >Cancel</Button>
        </ModalFooter>
    </Form>
</Modal>
