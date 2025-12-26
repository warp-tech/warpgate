<script lang="ts">
    import { faCheck, faInfoCircle } from '@fortawesome/free-solid-svg-icons'
    import {
        Button,
        FormGroup,
        Input,
        Modal,
        ModalBody,
        ModalFooter,
    } from '@sveltestrap/sveltestrap'
    import type { IssuedCertificateCredential } from 'admin/lib/api'
    import AsyncButton from 'common/AsyncButton.svelte'
    import CopyButton from 'common/CopyButton.svelte'
    import Alert from 'common/sveltestrap-s5-ports/Alert.svelte'
    import Fa from 'svelte-fa'

    interface Props {
        isOpen: boolean
        username: string
        save: (label: string, publicKeyPem: string) => Promise<IssuedCertificateCredential>
        onClose?: () => void
    }

    let {
        isOpen = $bindable(false),
        username,
        save,
        onClose,
    }: Props = $props()

    let saving = $state(false)
    let privateKeyPem = $state('')
    let publicKeyPem = $state('')
    let label = $state('')
    let generatedCertificatePem = $state('')
    let generatedKubeConfig = $state('')

    async function generateKeyPair() {
        try {
            const keyPair = await crypto.subtle.generateKey(
                {
                    name: 'ECDSA',
                    namedCurve: 'P-384',
                },
                true,
                ['sign', 'verify']
            )

            // Export private key as PKCS#8 PEM
            const privateKeyArrayBuffer = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey)
            const privateKeyBase64 = btoa(String.fromCharCode(...new Uint8Array(privateKeyArrayBuffer)))
            const privateKeyLines = privateKeyBase64.match(/.{1,64}/g) || []
            privateKeyPem = `-----BEGIN PRIVATE KEY-----\n${privateKeyLines.join('\n')}\n-----END PRIVATE KEY-----`

            // Export public key as SPKI PEM
            const publicKeyArrayBuffer = await crypto.subtle.exportKey('spki', keyPair.publicKey)
            const publicKeyBase64 = btoa(String.fromCharCode(...new Uint8Array(publicKeyArrayBuffer)))
            const publicKeyLines = publicKeyBase64.match(/.{1,64}/g) || []
            publicKeyPem = `-----BEGIN PUBLIC KEY-----\n${publicKeyLines.join('\n')}\n-----END PUBLIC KEY-----`
        } catch (error) {
            console.error('Failed to generate key pair:', error)
            alert('Failed to generate key pair. Please try again.')
        }
    }

    async function _generate() {
        if (!label.trim()) {
            alert('Please provide a label')
            return
        }

        saving = true
        try {
            await generateKeyPair()

            if (!publicKeyPem) {
                throw new Error('Failed to generate key pair')
            }

            // Then submit public key to get certificate issued
            const result = await save(label.trim(), publicKeyPem)
            generatedCertificatePem = result.certificatePem

            generatedKubeConfig = `- name: ${username}\n  user:\n    client-certificate-data: ${btoa(generatedCertificatePem)}\n    client-key-data: ${btoa(privateKeyPem)}`
        } catch (error) {
            console.error('Failed to generate certificate:', error)
            alert('Failed to generate certificate. Please try again.')
        } finally {
            saving = false
        }
    }

    function downloadBlob(content: string, filename: string) {
        const blob = new Blob([content], { type: 'text/plain' })
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = filename
        document.body.appendChild(a)
        a.click()
        document.body.removeChild(a)
        URL.revokeObjectURL(url)
    }

    function downloadPrivateKey() {
        if (!privateKeyPem) {
            return
        }
        const filename = label.trim() ? `${label.trim()}-private-key.pem` : 'private-key.pem'
        downloadBlob(privateKeyPem, filename)
    }

    function downloadCertificate() {
        if (!generatedCertificatePem) {
            return
        }
        const certLabel = label.trim() || 'certificate'
        const filename = `${certLabel}-certificate.pem`
        downloadBlob(generatedCertificatePem, filename)
    }

    function close() {
        isOpen = false
        privateKeyPem = ''
        publicKeyPem = ''
        label = ''
        generatedCertificatePem = ''
        saving = false
        onClose?.()
    }
</script>

<Modal {isOpen} toggle={close}>
    <ModalBody>
        {#if generatedCertificatePem}
            <div class="text-center mb-3">
                <Fa icon={faCheck} class="m-auto" size="lg" />
                <p>Certificate has been issued</p>
            </div>
            <Alert color="warning" fade={false} class="mb-3">
                You must download the private key and the certificate now - you won't be possible to access them later.
            </Alert>
        {:else}
            <FormGroup floating label="Certificate label">
                <Input
                    bind:value={label}
                    disabled={saving}
                />
            </FormGroup>

            <div class="text-muted d-flex align-items-center">
                <Fa icon={faInfoCircle} class="me-3" />
                <small>
                    A private key will be generated locally in your browser.
                    <br/>
                    You'll need to save it after the certificate is issued.
                </small>
            </div>
        {/if}
    </ModalBody>
    <ModalFooter>
        {#if !generatedCertificatePem}
            <AsyncButton
                color="primary"
                class="modal-button"
                disabled={saving || !label.trim()}
                click={_generate}
            >
                Issue certificate
            </AsyncButton>
        {:else}
            <Button
                color="primary"
                class="d-block w-100"
                on:click={downloadCertificate}
            >
                Save certificate
            </Button>
        {/if}
        {#if privateKeyPem}
            <Button
                color="primary"
                class="d-block w-100"
                on:click={downloadPrivateKey}
            >
                Save private key
            </Button>
        {/if}
        {#if generatedKubeConfig}
            <CopyButton
                color="secondary"
                class="d-flex align-items-center justify-content-center w-100"
                text={generatedKubeConfig}
                label="Copy both as kubeconfig"
                />
        {/if}
        <Button
            color="danger"
            on:click={close}
            class="modal-button"
        >Close</Button>
    </ModalFooter>
</Modal>
