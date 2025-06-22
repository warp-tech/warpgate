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

    import type { ExistingCertificateCredential } from './lib/api'

    interface Props {
        isOpen: boolean
        instance?: ExistingCertificateCredential
        save: (label: string, certificate: string) => void
    }

    let {
        isOpen = $bindable(true),
        instance,
        save,
    }: Props = $props()

    let field: HTMLInputElement|undefined = $state()
    let label: string = $state('')
    let certificate: string = $state('')
    let validated = $state(false)

    const CERT_REGEX = /^-----BEGIN CERTIFICATE-----[\s\S]*-----END CERTIFICATE-----$/

    function _save () {
        if (!certificate || !label) {
            return
        }
        // Clean up the certificate (remove extra whitespace, ensure proper formatting)
        certificate = certificate.trim()
        if (!certificate.startsWith('-----BEGIN CERTIFICATE-----')) {
            certificate = '-----BEGIN CERTIFICATE-----\n' + certificate
        }
        if (!certificate.endsWith('-----END CERTIFICATE-----')) {
            certificate = certificate + '\n-----END CERTIFICATE-----'
        }
        isOpen = false
        save(label, certificate)
    }

    function _cancel () {
        isOpen = false
    }

    $effect(() => field?.addEventListener('paste', e => {
        const clipboardData = e.clipboardData
        if (clipboardData) {
            const newValue = clipboardData.getData('text')
            onCertificatePaste(newValue)
        }
    }))

    function onCertificatePaste (newValue: string) {
        // Try to extract a common name or subject from the certificate for auto-labeling
        // This is just a simple heuristic
        if (!label && newValue.includes('-----BEGIN CERTIFICATE-----')) {
            // Could parse the certificate to extract CN, but for now just use a generic label
            label = 'Certificate'
        }
    }
</script>

<Modal toggle={_cancel} isOpen={isOpen} on:open={() => {
    if (instance) {
        label = instance.label
        // Note: we can't populate the certificate field as it's not returned by the API for security
    }
    field?.focus()
}}>
    <Form {validated} on:submit={e => {
        _save()
        e.preventDefault()
    }}>
        <ModalBody>
            <FormGroup floating label="Label">
                <Input
                    bind:inner={field}
                    type="text"
                    required
                    bind:value={label} />
            </FormGroup>
            <FormGroup floating label="Certificate in PEM format" spacing="0">
                <Input
                    style="font-family: monospace; height: 15rem"
                    bind:inner={field}
                    type="textarea"
                    required
                    placeholder="-----BEGIN CERTIFICATE-----&#10;MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...&#10;-----END CERTIFICATE-----"
                    bind:value={certificate} />
            </FormGroup>
            {#if certificate && !CERT_REGEX.test(certificate.trim())}
                <div class="text-danger small">
                    Certificate must be in PEM format (-----BEGIN CERTIFICATE----- ... -----END CERTIFICATE-----)
                </div>
            {/if}
        </ModalBody>
        <ModalFooter>
            <Button
                type="submit"
                color="primary"
                class="modal-button"
                disabled={!certificate || !label || !CERT_REGEX.test(certificate.trim())}
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
