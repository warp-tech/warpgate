<script lang="ts">
import { onMount } from 'svelte'
import { Alert, Button, FormGroup, Input, Modal, ModalBody, ModalFooter, ModalHeader } from 'sveltestrap'
import QRCode from 'qrcode'
import { KeyEncodings, TOTP, TOTPOptions } from '@otplib/core'
import { createDigest } from '@otplib/plugin-crypto-js'
import { faRefresh } from '@fortawesome/free-solid-svg-icons'
import Fa from 'svelte-fa'
import base32Encode from 'base32-encode'

import { api } from 'gateway/lib/api'
import type { UserAuthCredential } from './lib/api'

export let credential: UserAuthCredential
export let username: string
export let save: () => void
export let cancel: () => void
let visible = true
let newPassword = ''
let field: HTMLInputElement|undefined
let qrImage: HTMLImageElement|undefined

export const totp = new TOTP<TOTPOptions>({
    createDigest,
})

function _save () {
    if (credential.kind === 'Password') {
        if (!newPassword) {
            return
        }
        credential.hash = newPassword
    }
    visible = false
    save()
}

function generateNewTotpKey () {
    if (credential.kind === 'Totp') {
        credential.key = Array.from({ length: 32 }, () => Math.floor(Math.random() * 255))
    }
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

$: {
    if (credential.kind === 'Totp') {
        if (!credential.key.length) {
            generateNewTotpKey()
        }

        const uri = totp.keyuri(username, 'Warpgate', base32Encode(new Uint8Array(credential.key), 'RFC4648'))

        QRCode.toDataURL(uri, (err, imageUrl) => {
            if (err) {
                console.log('Error with QR')
                return
            }
            if (qrImage) {
                qrImage.src = imageUrl
            }
        })
    }
}
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
                        <option value="" selected>Any</option>
                        {#each providers as provider}
                            <option value={provider.name}>{provider.label ?? provider.name}</option>
                        {/each}
                    </Input>
                </FormGroup>
            {/await}
        {/if}

        {#if credential.kind === 'Password'}
            <Input
                bind:inner={field}
                type="password"
                placeholder="New password"
                bind:value={newPassword} />
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
                    <Button outline class="d-flex align-items-center" color="primary" on:click={generateNewTotpKey}>
                        <Fa class="me-2" fw icon={faRefresh} />
                        Reset secret key
                    </Button>
                </div>
            </div>
        {/if}
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
