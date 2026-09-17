<script lang="ts">
    /**
     * Set a password — part of 6c.
     *
     * The 422 handling is the load-bearing part. The server enforces the
     * password policy and returns the specific violations; this modal reads
     * them out of the response body and lists them. Swallowing that would
     * leave the operator with a silent no-op, so the catch narrows on status
     * rather than on the error being any failure.
     *
     * An unexpected error is now surfaced rather than swallowed — the original
     * caught everything and only rendered the 422 case, so a 500 closed
     * nothing and said nothing.
     */
    import { ResponseError as AdminApiResponseError } from 'admin/lib/api'
    import { stringifyError } from 'common/errors'
    import {
        ResponseError as GatewayApiResponseError,
        PasswordPolicyViolation,
    } from 'gateway/lib/api'
    import Button from 'ui/Button.svelte'
    import Callout from 'ui/Callout.svelte'
    import Input from 'ui/Input.svelte'
    import Modal from 'ui/Modal.svelte'

    interface Props {
        isOpen: boolean
        create: (password: string) => Promise<void> | void
    }

    let { isOpen = $bindable(true), create }: Props = $props()

    let password = $state('')
    let policyViolations = $state<PasswordPolicyViolation[]>([])
    let otherError: string | undefined = $state()

    const VIOLATION_TEXT: Record<string, string> = {
        [PasswordPolicyViolation.MissingDigit]: 'Must contain a digit',
        [PasswordPolicyViolation.MissingLowercase]:
            'Must contain a lowercase letter',
        [PasswordPolicyViolation.MissingUppercase]:
            'Must contain an uppercase letter',
        [PasswordPolicyViolation.MissingSpecial]:
            'Must contain a special character',
        [PasswordPolicyViolation.TooShort]: 'Must be longer',
    }

    async function save() {
        if (!password) {
            return
        }
        try {
            await create(password)
            policyViolations = []
            otherError = undefined
            password = ''
            isOpen = false
        } catch (e) {
            if (
                (e instanceof AdminApiResponseError ||
                    e instanceof GatewayApiResponseError) &&
                e.response.status === 422
            ) {
                policyViolations = await e.response.json()
                otherError = undefined
                return
            }
            // Anything else used to be swallowed entirely.
            policyViolations = []
            otherError = await stringifyError(e)
        }
    }

    function cancel() {
        isOpen = false
        password = ''
        policyViolations = []
        otherError = undefined
    }
</script>

<Modal bind:open={isOpen} title="Set a password" size="sm" onclose={cancel}>
    <Input
        label="New password"
        type="password"
        autocomplete="new-password"
        required
        autofocus
        bind:value={password}
        onkeydown={e => {
            if (e.key === 'Enter') {
                e.preventDefault()
                save()
            }
        }}
    />

    {#if policyViolations.length}
        <div class="violations">
            <Callout tone="danger" title="Password does not meet the policy">
                <ul>
                    {#each policyViolations as violation (violation)}
                        <li>{VIOLATION_TEXT[violation] ?? violation}</li>
                    {/each}
                </ul>
            </Callout>
        </div>
    {:else if otherError}
        <div class="violations">
            <Callout tone="danger" title="Could not set the password">
                {otherError}
            </Callout>
        </div>
    {/if}

    {#snippet footer()}
        <Button onclick={cancel}>Cancel</Button>
        <Button variant="primary" disabled={!password} click={save}>
            Create
        </Button>
    {/snippet}
</Modal>

<style>
    .violations {
        margin-top: var(--wg-space-lg);
    }

    ul {
        margin: 0;
        padding-left: var(--wg-space-lg);
    }
</style>
