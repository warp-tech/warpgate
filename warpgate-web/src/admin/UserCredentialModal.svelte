<script lang="ts">
    import {
        Alert,
        Button,
        FormGroup,
        Input,
        Modal,
        ModalBody,
        ModalFooter,
    } from '@sveltestrap/sveltestrap'
    import QRCode from 'qrcode'
    import * as OTPAuth from 'otpauth'
    import { faClipboard, faRefresh } from '@fortawesome/free-solid-svg-icons'
    import Fa from 'svelte-fa'
    import base32Encode from 'base32-encode'

    import { api } from 'gateway/lib/api'
    import type { UserAuthCredential, UserTotpCredential } from './lib/api'
    import ModalHeader from 'common/ModalHeader.svelte'
    import { onMount } from 'svelte'

    interface Props {
        credential: UserAuthCredential;
        username: string;
        save: () => void;
        cancel: () => void;
    }

    let {
        credential = $bindable(),
        username,
        save,
        cancel,
    }: Props = $props()
    let visible = $state(true)
    let newPassword = $state('')
    let field: HTMLInputElement|undefined = $state()
    let qrImage: HTMLImageElement|undefined = $state()
    let totpUri: string|undefined = $state()
    let totpValidationValue: string|undefined = $state()
    let validationFeedback: string|undefined = $state()
    let totpValid = $state(false)
    let passwordValid = $state(false)

    export const totp = $state(new OTPAuth.TOTP({
        issuer: 'Warpgate',
        digits: 6,
        period: 30,
        algorithm: 'SHA1',
    }))

    function _save () {

        if (credential.kind === 'Password') {
            if (!newPassword) {
                return
            }
            credential.hash = newPassword
        }
        if (credential.kind === 'PublicKey') {
            if (credential.key.includes(' ')) {
                const parts = credential.key.split(' ').filter(x => x)
                credential.key = `${parts[0]} ${parts[1]}`
            }
        }
        visible = false
        save()
    }

    function _validate () : boolean {
        console.debug(`Validating credentials of kind "${credential.kind}"`)

        if (credential.kind === 'Totp' && totpValidationValue) {
            totp.secret ??= OTPAuth.Secret.fromBase32(encodeTotpSecret(credential))
            totpValid = totp.validate({ token: totpValidationValue, window: 1 }) !== null

            if (!totpValid) {
                validationFeedback = 'The TOTP code is not valid'
            } else {
                validationFeedback = undefined
            }

            return totpValid
        } else if (credential.kind === 'Password') {
            passwordValid = newPassword.trim().length > 1

            if (!passwordValid) {
                validationFeedback = 'Password cannot be empty or whitespace'
            } else {
                validationFeedback = undefined
            }

            return passwordValid
        } else {
            // TODO: Further validation
            return true
        }
    }

    function generateNewTotpKey () {
        if (credential.kind === 'Totp') {
            credential.key = Array.from({ length: 32 }, () => Math.floor(Math.random() * 255))
        }
    }

    /**
    * Copies the TOTP URI to the system clipboard if it is defined.
    *
    * @return {Promise<void>} A promise that resolves when the TOTP URI has been copied to the clipboard.
    */
    async function copyTotpUri () : Promise<void> {
        if (totpUri === undefined) {
            return
        }

        const { clipboard } = navigator
        return clipboard.writeText(totpUri)
    }

    function _cancel () {
        visible = false
        cancel()
    }

    onMount(() => {
        setTimeout(() => {
            field?.focus()
        })
    })


    /**
    * Generates a TOTP (Time-based One-Time Password) secret key encoded in base32.
    *
    * @param {UserTotpCredential} cred - The credential containing a key for TOTP generation.
    * @return {string} The base32 encoded TOTP secret key.
    */
    function encodeTotpSecret (cred: UserTotpCredential) : string {
        return base32Encode(new Uint8Array(cred.key), 'RFC4648')
    }

    $effect(() => {
        if (credential.kind === 'Totp') {
            if (!credential.key.length) {
                generateNewTotpKey()
            }

            totp.label = username
            totp.secret = OTPAuth.Secret.fromBase32(encodeTotpSecret(credential))
            totpUri = totp.toString()

            QRCode.toDataURL(totpUri, (err: Error | null | undefined, imageUrl: string) => {
                if (err) {
                    return
                }
                if (qrImage) {
                    qrImage.src = imageUrl
                }
            })
        }

        _validate()
    })
</script>

<Modal toggle={cancel} isOpen={visible}>
    <ModalHeader toggle={cancel}>
        {#if credential.kind === 'Sso'}
            Single sign-on
        {/if}
        {#if credential.kind === 'Password'}
            Password
        {/if}
        {#if credential.kind === 'Totp'}
            One-time password
        {/if}
        {#if credential.kind === 'PublicKey'}
            Public key
        {/if}
    </ModalHeader>
    <ModalBody>
        {#if credential.kind === 'Sso'}
            <FormGroup floating label="E-mail">
                <Input
                    bind:inner={field}
                    type="email"
                    bind:value={credential.email} />
            </FormGroup>

            {#await api.getSsoProviders() then providers}
                {#if !providers.length}
                    <Alert color="warning">
                        You don't have any SSO providers configured. Add them to your config file first.
                    </Alert>
                {/if}
                <FormGroup floating label="SSO provider">
                    <Input
                        bind:value={credential.provider}
                        type="select"
                    >
                        <option value={null} selected>Any</option>
                        {#each providers as provider}
                            <option value={provider.name}>{provider.label ?? provider.name}</option>
                        {/each}
                    </Input>
                </FormGroup>
            {/await}
        {/if}

        {#if credential.kind === 'Password'}
            <FormGroup floating class="mt-3" label="Enter a new password">
                <Input
                    bind:inner={field}
                    bind:feedback={validationFeedback}
                    type="password"
                    placeholder="New password"
                    valid={passwordValid}
                    invalid={!passwordValid}
                    on:change={_validate}
                    bind:value={newPassword} />
            </FormGroup>
        {/if}

        {#if credential.kind === 'PublicKey'}
            <Input
                style="font-family: monospace; height: 15rem"
                bind:inner={field}
                type="textarea"
                placeholder="ssh-XXX YYYYYY"
                bind:value={credential.key} />
        {/if}

        {#if credential.kind === 'Totp'}
            <div class="row">
                <div class="col-12 col-md-6">
                    <img class="qr" bind:this={qrImage} alt="OTP QR code" />
                </div>
                <div class="col-12 col-md-6">
                    <Button outline class="d-flex align-items-center" color="link" on:click={generateNewTotpKey}>
                        <Fa class="me-2" fw icon={faRefresh} />
                        Reset secret key
                    </Button>
                    <Button outline class="d-flex align-items-center" color="link" on:click={copyTotpUri}>
                        <Fa class="me-2" fw icon={faClipboard} />
                        Copy raw value
                    </Button>
                </div>
            </div>
            <FormGroup floating label="Paste TOTP code for validation" class="mt-3">
                <Input
                    required
                    bind:feedback={validationFeedback}
                    bind:value={totpValidationValue}
                    valid={totpValid}
                    invalid={!totpValid}
                    pattern="\d{6}"
                    on:change={_validate}
                    on:keyup={_validate} />
            </FormGroup>
        {/if}
    </ModalBody>
    <ModalFooter>
        <div class="d-flex">
            <Button
                class="ms-auto"
                disabled={!_validate}
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

<style lang="scss">
    .qr {
        width: 15rem;
        max-width: 100%;
        margin: auto;
        border-radius: .5rem;
        background: white;
        opacity: .8;
    }
</style>
