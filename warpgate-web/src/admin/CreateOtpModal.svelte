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

    import ModalHeader from 'common/ModalHeader.svelte'
    import QRCode from 'qrcode'
    import * as OTPAuth from 'otpauth'
    import base32Encode from 'base32-encode'
    import Fa from 'svelte-fa'
    import { faClipboard, faRefresh } from '@fortawesome/free-solid-svg-icons'

    interface Props {
        isOpen: boolean
        username: string
        create: (secretKey: number[]) => void
    }

    let {
        isOpen = $bindable(true),
        username,
        create,
    }: Props = $props()
    let secretKey: number[] = $state([])
    let qrImage: HTMLImageElement|undefined = $state()
    let totpUri: string|undefined = $state()
    let totpValidationValue: string|undefined = $state()
    let field: HTMLInputElement|undefined = $state()
    let validated = $state(false)
    let totpValid = $state(false)
    let validationFeedback = $state<string|undefined>()

    const totp = $state(new OTPAuth.TOTP({
        issuer: 'Warpgate',
        digits: 6,
        period: 30,
        algorithm: 'SHA1',
    }))

    function _validate () : boolean {
        if (totpValidationValue) {
            totp.secret ??= OTPAuth.Secret.fromBase32(encodeTotpSecret(secretKey))
            totpValid = totp.validate({ token: totpValidationValue, window: 1 }) !== null

            if (!totpValid) {
                validationFeedback = 'The TOTP code is not valid'
            } else {
                validationFeedback = undefined
            }

            return totpValid
        }
        return true
    }

    function generateNewTotpKey () {
        secretKey = Array.from({ length: 32 }, () => Math.floor(Math.random() * 255))
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

    /**
    * Generates a TOTP (Time-based One-Time Password) secret key encoded in base32.
    *
    * @param {UserTotpCredential} cred - The credential containing a key for TOTP generation.
    * @return {string} The base32 encoded TOTP secret key.
    */
    function encodeTotpSecret (secretKey: number[]) : string {
        return base32Encode(new Uint8Array(secretKey), 'RFC4648')
    }

    $effect(() => {
        if (!secretKey.length) {
            generateNewTotpKey()
        }

        totp.label = username
        totp.secret = OTPAuth.Secret.fromBase32(encodeTotpSecret(secretKey))
        totpUri = totp.toString()

        QRCode.toDataURL(totpUri, (err: Error | null | undefined, imageUrl: string) => {
            if (err) {
                return
            }
            if (qrImage) {
                qrImage.src = imageUrl
            }
        })

        _validate()
    })

    function _save () {
        if (!secretKey) {
            return
        }
        isOpen = false
        create(secretKey)
    }

    function _cancel () {
        isOpen = false
    }
</script>

<Modal toggle={_cancel} isOpen={isOpen} on:open={() => field?.focus()}>
    <Form {validated} on:submit={e => {
        _save()
        e.preventDefault()
    }}>
        <ModalHeader toggle={_cancel}>
            Password
        </ModalHeader>
        <ModalBody>
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
                    pattern={'\\d{6}'}
                    on:change={_validate}
                    on:keyup={_validate} />
            </FormGroup>
        </ModalBody>
        <ModalFooter>
            <div class="d-flex">
                <Button
                    class="ms-auto"
                    disabled={!_validate}
                    outline
                    on:click={() => validated = true}
                >Create</Button>

                <Button
                    class="ms-2"
                    outline
                    color="danger"
                    on:click={_cancel}
                >Cancel</Button>
            </div>
        </ModalFooter>
    </Form>
</Modal>
