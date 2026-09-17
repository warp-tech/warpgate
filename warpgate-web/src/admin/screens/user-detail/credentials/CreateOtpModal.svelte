<script lang="ts">
    /**
     * TOTP enrolment — part of screen 6b.
     *
     * ── SECURITY FIX, not a presentation change ──────────────────────────
     * The original generated the shared secret with:
     *
     *     Array.from({ length: 32 }, () => Math.floor(Math.random() * 255))
     *
     * Two defects in one line:
     *
     *   1. `Math.random()` is not cryptographically secure. It is a seeded
     *      PRNG whose output is predictable to anyone who can observe enough
     *      of it or recover the engine's internal state. A TOTP shared secret
     *      generated this way can be derived rather than guessed, which makes
     *      the second factor decorative.
     *   2. `Math.floor(Math.random() * 255)` yields 0-254. The value 255 is
     *      never produced, so each byte carries slightly under 8 bits and the
     *      key space is smaller than 32 bytes implies.
     *
     * Replaced with `crypto.getRandomValues`, which produces the same shape —
     * 32 values in 0-255 — from a CSPRNG. Nothing observable about the
     * enrolment flow changes. Written up in UPSTREAM-ISSUES.md.
     *
     * ── Behaviour preserved ──────────────────────────────────────────────
     * Issuer "Warpgate", 6 digits, 30s period, SHA1; base32 RFC4648 encoding;
     * QR built from the otpauth:// URI; live validation with window:1 so a
     * code from the adjacent step still passes; Confirm disabled until a code
     * validates; the URI copyable for password managers that take it directly.
     */
    import base32Encode from 'base32-encode'
    import * as OTPAuth from 'otpauth'
    import QRCode from 'qrcode'
    import Button from 'ui/Button.svelte'
    import Callout from 'ui/Callout.svelte'
    import CopyButton from 'ui/CopyButton.svelte'
    import Input from 'ui/Input.svelte'
    import Modal from 'ui/Modal.svelte'

    interface Props {
        isOpen: boolean
        username: string
        create: (secretKey: number[]) => void
    }

    let { isOpen = $bindable(true), username, create }: Props = $props()

    let secretKey: number[] = $state([])
    let qrImage: HTMLImageElement | undefined = $state()
    let totpUri = $state('')
    let totpValidationValue = $state('')
    let totpValid = $state(false)
    let validationFeedback: string | undefined = $state()

    const totp = $state(
        new OTPAuth.TOTP({
            issuer: 'Warpgate',
            digits: 6,
            period: 30,
            algorithm: 'SHA1',
        }),
    )

    function generateNewTotpKey() {
        // CSPRNG, full 0-255 range. See the header for what this replaced.
        const bytes = new Uint8Array(32)
        crypto.getRandomValues(bytes)
        secretKey = Array.from(bytes)
    }

    function encodeTotpSecret(key: number[]): string {
        return base32Encode(new Uint8Array(key), 'RFC4648')
    }

    function validate(): boolean {
        if (!totpValidationValue) {
            totpValid = false
            validationFeedback = undefined
            return false
        }
        totp.secret = OTPAuth.Secret.fromBase32(encodeTotpSecret(secretKey))
        // window:1 accepts the adjacent step, so a code typed as the period
        // rolls over is not spuriously rejected.
        totpValid =
            totp.validate({ token: totpValidationValue, window: 1 }) !== null
        validationFeedback = totpValid
            ? undefined
            : 'That code is not valid. Check your device clock if it keeps failing.'
        return totpValid
    }

    $effect(() => {
        if (!secretKey.length) {
            generateNewTotpKey()
        }

        totp.label = username
        totp.secret = OTPAuth.Secret.fromBase32(encodeTotpSecret(secretKey))
        totpUri = totp.toString()

        QRCode.toDataURL(
            totpUri,
            (err: Error | null | undefined, url: string) => {
                if (err) {
                    return
                }
                if (qrImage) {
                    qrImage.src = url
                }
            },
        )

        validate()
    })

    function save() {
        if (!secretKey.length || !totpValid) {
            return
        }
        isOpen = false
        create(secretKey)
    }
</script>

<Modal bind:open={isOpen} title="Set up a one-time password" size="lg">
    <div class="layout">
        <div class="qr-column">
            <img class="qr" bind:this={qrImage} alt="TOTP enrolment QR code">
            <CopyButton text={totpUri} label="Copy setup URI" />
        </div>

        <ol class="steps">
            <li>
                Install a TOTP authenticator app, or use a password manager that
                supports one.
            </li>
            <li>Scan the code, or paste the setup URI into the app.</li>
            <li>
                <label class="step-label" for="totp-code">
                    Enter the code the app shows
                </label>
                <Input
                    id="totp-code"
                    label="One-time password"
                    labelHidden
                    mono
                    inputmode="numeric"
                    autocomplete="one-time-code"
                    placeholder="000000"
                    bind:value={totpValidationValue}
                    error={validationFeedback}
                    oninput={validate}
                />
            </li>
        </ol>
    </div>

    <Callout title="The code is checked before this is saved">
        Warpgate verifies the code against the secret now, so an enrolment that
        would not have worked cannot be saved. Keep the recovery path in mind if
        this is the user's only second factor.
    </Callout>

    {#snippet footer()}
        <Button onclick={() => (isOpen = false)}>Cancel</Button>
        <Button variant="primary" disabled={!totpValid} onclick={save}>
            Confirm
        </Button>
    {/snippet}
</Modal>

<style>
    .layout {
        display: flex;
        gap: var(--wg-space-xl);
        margin-bottom: var(--wg-space-lg);
    }

    .qr-column {
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: var(--wg-space-md);
        flex: none;
    }

    /* White ground regardless of theme: a QR inverted by a dark palette is
     * unreadable to most scanners. */
    .qr {
        width: 160px;
        height: 160px;
        padding: var(--wg-space-sm);
        background: #fff;
        border-radius: var(--wg-radius);
    }

    .steps {
        margin: 0;
        padding-left: var(--wg-space-lg);
        display: flex;
        flex-direction: column;
        gap: var(--wg-space-md);
        font: var(--wg-text-body-md);
        color: var(--wg-text);
    }

    .step-label {
        display: block;
        margin-bottom: var(--wg-space-xs);
        color: var(--wg-text-muted);
    }

    @media (max-width: 720px) {
        .layout {
            flex-direction: column;
            align-items: center;
        }
    }
</style>
