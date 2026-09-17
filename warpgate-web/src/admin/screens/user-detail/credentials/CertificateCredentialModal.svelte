<script lang="ts">
    /**
     * Issue a client certificate — part of 6c.
     *
     * ── What this flow actually is ───────────────────────────────────────
     * The private key is generated in the browser with WebCrypto (ECDSA
     * P-384) and never sent to Warpgate: only the SPKI public key goes to the
     * server, which returns a certificate signed against it. That is why the
     * "save it now" warning matters — nobody, including the server, can
     * produce the private key again afterwards.
     *
     * ── Behaviour preserved ──────────────────────────────────────────────
     * Key generation and both PEM exports, certificate issuance, optional
     * storage in the browser for kubeconfig generation, the kubeconfig
     * snippet, downloads for key and certificate, the reset on close, and the
     * auto-close when `storeInBrowserByDefault` is set and storage succeeded.
     *
     * ── Changed: two native alert() calls removed ────────────────────────
     * The original used `alert()` for a missing label and for a failed
     * generation. The first is now prevented by disabling the button, and the
     * second is a Callout carrying the actual error, which `alert('Failed to
     * generate certificate. Please try again.')` discarded — the real cause
     * only reached the console. A failure inside generateKeyPair() also used
     * to raise two alerts in a row: it caught and alerted, then let the caller
     * throw and alert again.
     *
     * ── Fixed: key material survived close() ─────────────────────────────
     * The original reset everything except `generatedKubeConfig`, and the
     * footer tested that variable at the top level rather than nested under
     * the issued branch. Reopening the modal for a second credential
     * therefore showed a live "Copy both as kubeconfig" button still holding
     * the *previous* certificate's private key. It is reset here with the
     * rest.
     */
    import type { IssuedCertificateCredential } from 'admin/lib/api'
    import { stringifyError } from 'common/errors'
    import { downloadBlob } from 'common/helpers'
    import { saveCertificateKey } from 'gateway/lib/certificateStore'
    import 'ui/forms.css'
    import Button from 'ui/Button.svelte'
    import Callout from 'ui/Callout.svelte'
    import Checkbox from 'ui/Checkbox.svelte'
    import CopyButton from 'ui/CopyButton.svelte'
    import Input from 'ui/Input.svelte'
    import Modal from 'ui/Modal.svelte'

    interface Props {
        isOpen: boolean
        username: string
        save: (
            label: string,
            publicKeyPem: string,
        ) => Promise<IssuedCertificateCredential>
        onClose?: () => void
        storeInBrowserByDefault?: boolean
    }

    let {
        isOpen = $bindable(false),
        username,
        save,
        onClose,
        storeInBrowserByDefault = false,
    }: Props = $props()

    let privateKeyPem = $state('')
    let publicKeyPem = $state('')
    let label = $state('')
    let generatedCertificatePem = $state('')
    let generatedKubeConfig = $state('')
    let storeInBrowser = $state(false)
    let error: string | undefined = $state()
    // Button owns its own pending state, but the label field has to lock too:
    // editing it mid-flight would name the downloaded files after a label the
    // issued certificate does not carry.
    let saving = $state(false)

    $effect(() => {
        if (isOpen) {
            storeInBrowser = storeInBrowserByDefault
        }
    })

    function toPem(buffer: ArrayBuffer, kind: 'PRIVATE KEY' | 'PUBLIC KEY') {
        const base64 = btoa(String.fromCharCode(...new Uint8Array(buffer)))
        const lines = base64.match(/.{1,64}/g) ?? []
        return `-----BEGIN ${kind}-----\n${lines.join('\n')}\n-----END ${kind}-----`
    }

    async function generateKeyPair() {
        const keyPair = await crypto.subtle.generateKey(
            { name: 'ECDSA', namedCurve: 'P-384' },
            true,
            ['sign', 'verify'],
        )
        privateKeyPem = toPem(
            await crypto.subtle.exportKey('pkcs8', keyPair.privateKey),
            'PRIVATE KEY',
        )
        publicKeyPem = toPem(
            await crypto.subtle.exportKey('spki', keyPair.publicKey),
            'PUBLIC KEY',
        )
    }

    async function generate() {
        if (!label.trim()) {
            return
        }
        error = undefined
        saving = true
        try {
            await generateKeyPair()
            if (!publicKeyPem) {
                throw new Error('Key pair generation produced no public key')
            }

            const result = await save(label.trim(), publicKeyPem)
            generatedCertificatePem = result.certificatePem

            if (storeInBrowser) {
                await saveCertificateKey({
                    credentialId: result.credential.id,
                    privateKeyPem,
                    certificatePem: result.certificatePem,
                })
            }

            generatedKubeConfig = `- name: ${username}\n  user:\n    client-certificate-data: ${btoa(generatedCertificatePem)}\n    client-key-data: ${btoa(privateKeyPem)}`

            if (storeInBrowser && storeInBrowserByDefault) {
                closeModal()
            }
        } catch (err) {
            // The original discarded this and showed a fixed string.
            error = await stringifyError(err)
        } finally {
            saving = false
        }
    }

    function downloadPrivateKey() {
        if (!privateKeyPem) {
            return
        }
        // Matches the original's fallback exactly: bare 'private-key.pem',
        // not 'private-key-private-key.pem'.
        const name = label.trim()
        downloadBlob(
            privateKeyPem,
            name ? `${name}-private-key.pem` : 'private-key.pem',
        )
    }

    function downloadCertificate() {
        if (!generatedCertificatePem) {
            return
        }
        const name = label.trim() || 'certificate'
        downloadBlob(generatedCertificatePem, `${name}-certificate.pem`)
    }

    // Named to avoid shadowing window.close
    function closeModal() {
        isOpen = false
        privateKeyPem = ''
        publicKeyPem = ''
        label = ''
        generatedCertificatePem = ''
        generatedKubeConfig = ''
        storeInBrowser = false
        error = undefined
        saving = false
        onClose?.()
    }

    const issued = $derived(!!generatedCertificatePem)
</script>

<Modal
    bind:open={isOpen}
    title={issued ? 'Certificate issued' : 'Issue a certificate'}
    size="md"
    onclose={closeModal}
>
    {#if issued}
        <Callout
            tone="warning"
            title="Save these now — they cannot be recovered"
        >
            The private key was generated in this browser and never sent to
            Warpgate, so nothing can produce it again once this dialog closes.
            Download both files, or copy the kubeconfig, before continuing.
        </Callout>
    {:else}
        <div class="wg-field-stack">
            <Input
                label="Certificate label"
                required
                autofocus
                disabled={saving}
                bind:value={label}
            />

            <Callout title="The private key stays in this browser">
                Warpgate generates the key pair locally and only sends the
                public half. You will need to save the private key once the
                certificate is issued.
            </Callout>

            <!--
                Also locked in flight: `storeInBrowser` is read after the
                await, so toggling it mid-request decided the outcome.
            -->
            <Checkbox
                label="Store the certificate and private key in this browser"
                hint="Needed for kubeconfig generation from this machine. Anyone with access to this browser profile can then use them."
                disabled={saving}
                bind:checked={storeInBrowser}
            />
        </div>
    {/if}

    {#if error}
        <div class="error-slot">
            <Callout tone="danger" title="Could not issue the certificate">
                {error}
            </Callout>
        </div>
    {/if}

    {#snippet footer()}
        {#if !issued}
            <Button disabled={saving} onclick={closeModal}>Cancel</Button>
            <Button
                variant="primary"
                disabled={saving || !label.trim()}
                click={generate}
            >
                Issue certificate
            </Button>
        {:else}
            <div class="issued-actions">
                <Button variant="primary" onclick={downloadCertificate}>
                    Save certificate
                </Button>
                {#if privateKeyPem}
                    <Button variant="primary" onclick={downloadPrivateKey}>
                        Save private key
                    </Button>
                {/if}
                {#if generatedKubeConfig}
                    <CopyButton
                        text={generatedKubeConfig}
                        label="Copy both as kubeconfig"
                    />
                {/if}
                <Button onclick={closeModal}>Close</Button>
            </div>
        {/if}
    {/snippet}
</Modal>

<style>
    .error-slot {
        margin-top: var(--wg-space-lg);
    }

    .issued-actions {
        display: flex;
        flex-wrap: wrap;
        gap: var(--wg-space-sm);
        width: 100%;
        justify-content: flex-end;
    }
</style>
