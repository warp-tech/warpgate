<script lang="ts">
    import { ResponseError as AdminApiResponseError } from 'admin/lib/api'
    import { ResponseError as GatewayApiResponseError, PasswordPolicyViolation } from 'gateway/lib/api'
    import {
        Button,
        Form,
        FormGroup,
        Input,
        Modal,
        ModalBody,
        ModalFooter,
    } from '@sveltestrap/sveltestrap'
    import Alert from 'common/sveltestrap-s5-ports/Alert.svelte'

    interface Props {
        isOpen: boolean
        create: (password: string) => Promise<void> | void
    }

    let {
        isOpen = $bindable(true),
        create,
    }: Props = $props()
    let password = $state('')
    let policyViolations = $state<PasswordPolicyViolation[]>([])
    let field: HTMLInputElement|undefined = $state()
    let validated = $state(false)

    async function _save () {
        if (!password) {
            return
        }
        try {
            await create(password)
            policyViolations = []
            password = ''
            isOpen = false
        } catch (e) {
            if ((e instanceof AdminApiResponseError || e instanceof GatewayApiResponseError) && e.response.status === 422) {
                policyViolations = await e.response.json()
            }
        }
    }

    function _cancel () {
        isOpen = false
        password = ''
    }
</script>

<Modal toggle={_cancel} isOpen={isOpen} on:open={() => field?.focus()}>
    <Form {validated} on:submit={e => {
        _save()
        e.preventDefault()
    }}>
        <ModalBody>
            <FormGroup floating label="Enter a new password" spacing="0">
                <Input
                    bind:inner={field}
                    type="password"
                    placeholder="New password"
                    required
                    autocomplete="new-password"
                    bind:value={password} />
            </FormGroup>
            {#if policyViolations.length}
            <Alert color="danger">
                Password must meet the following requirements:
                <ul class="m-0">
                    {#each policyViolations as violation (violation)}
                        <li>
                            {#if violation === PasswordPolicyViolation.MissingDigit}
                                Must contain a digit
                            {:else if violation === PasswordPolicyViolation.MissingLowercase}
                                Must contain a lowercase letter
                            {:else if violation === PasswordPolicyViolation.MissingUppercase}
                                Must contain an uppercase letter
                            {:else if violation === PasswordPolicyViolation.MissingSpecial}
                                Must contain a special character
                            {:else if violation === PasswordPolicyViolation.TooShort}
                                Must be longer
                            {/if}
                        </li>
                    {/each}
                </ul>
            </Alert>
            {/if}
        </ModalBody>
        <ModalFooter>
            <Button
                class="modal-button"
                color="primary"
                on:click={() => validated = true}
            >Create</Button>

            <Button
                class="modal-button"
                color="danger"
                on:click={_cancel}
            >Cancel</Button>
        </ModalFooter>
    </Form>
</Modal>
