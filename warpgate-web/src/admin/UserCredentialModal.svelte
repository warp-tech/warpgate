<script lang="ts">
import { api } from 'gateway/lib/api'
import { onMount } from 'svelte'
import { Alert, Button, FormGroup, Input, Modal, ModalBody, ModalFooter, ModalHeader } from 'sveltestrap'
import QRCode from 'qrcode'
import { KeyEncodings, TOTP, TOTPOptions } from '@otplib/core'
import { createDigest, createRandomBytes } from '@otplib/plugin-crypto-js'
import { keyDecoder, keyEncoder } from '@otplib/plugin-base32-enc-dec'
import base32Encode from 'base32-encode'

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
        let key = ''
        if (!credential.key.length) {
            key = createRandomBytes(32, KeyEncodings.ASCII)
            credential.key = Array.from(key).map(x => x.charCodeAt(0))
        } else {
            key = credential.key.map(x => String.fromCharCode(x)).join('')
        }

        const uri = totp.keyuri(username, 'Warpgate', base32Encode(new Uint8Array(credential.key), 'RFC4648'))
        console.log(uri)

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
            <img bind:this={qrImage} />
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
