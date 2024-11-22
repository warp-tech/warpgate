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
    import { type ExistingSsoCredential } from './lib/api'
    import { api } from 'gateway/lib/api'
    import Alert from 'common/Alert.svelte'

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
    let email: string|null = $state('')

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
    <ModalHeader toggle={_cancel}>
        Single sign-on
    </ModalHeader>
    <ModalBody>
        <FormGroup floating label="E-mail">
            <Input
                type="email"
                bind:value={email} />
        </FormGroup>

        {#await api.getSsoProviders() then providers}
            {#if !providers.length}
                <Alert color="warning">
                    You don't have any SSO providers configured. Add them to your config file first.
                </Alert>
            {/if}
            <FormGroup floating label="SSO provider">
                <Input
                    bind:value={provider}
                    type="select"
                >
                    <option value={null} selected>Any</option>
                    {#each providers as provider}
                        <option value={provider.name}>{provider.label ?? provider.name}</option>
                    {/each}
                </Input>
            </FormGroup>
        {/await}
    </ModalBody>
    <ModalFooter>
        <div class="d-flex">
            <Button
                class="ms-auto"
                outline
                on:click={_save}
            >Save</Button>

            <Button
                class="ms-2"
                outline
                color="danger"
                on:click={_cancel}
            >Cancel</Button>
        </div>
    </ModalFooter>
</Modal>
