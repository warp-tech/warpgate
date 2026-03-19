import { api, type ExistingCertificateCredential } from 'gateway/lib/api'
import { saveCertificateKey, getCertificateKey, getAllCertificateKeys, type StoredCertificateKey } from './certificateStore'

export interface CertificateCredentialResult {
    certificatePem: string
    privateKeyPem: string
}

export interface CertificateWithKeyStatus {
    credential: ExistingCertificateCredential
    hasLocalKey: boolean
}

async function generateKeyPair (): Promise<{ publicKeyPem: string, privateKeyPem: string }> {
    const keyPair = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-384' },
        true,
        ['sign', 'verify'],
    )

    const privateKeyArrayBuffer = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey)
    const privateKeyBase64 = btoa(String.fromCharCode(...new Uint8Array(privateKeyArrayBuffer)))
    const privateKeyLines = privateKeyBase64.match(/.{1,64}/g) || []
    const privateKeyPem = `-----BEGIN PRIVATE KEY-----\n${privateKeyLines.join('\n')}\n-----END PRIVATE KEY-----`

    const publicKeyArrayBuffer = await crypto.subtle.exportKey('spki', keyPair.publicKey)
    const publicKeyBase64 = btoa(String.fromCharCode(...new Uint8Array(publicKeyArrayBuffer)))
    const publicKeyLines = publicKeyBase64.match(/.{1,64}/g) || []
    const publicKeyPem = `-----BEGIN PUBLIC KEY-----\n${publicKeyLines.join('\n')}\n-----END PUBLIC KEY-----`

    return { publicKeyPem, privateKeyPem }
}

function getBrowserLabel (): string {
    const ua = navigator.userAgent
    let browser = 'Unknown browser'
    let os = 'Unknown OS'

    if (ua.includes('Firefox/')) {
        browser = 'Firefox'
    } else if (ua.includes('Edg/')) {
        browser = 'Edge'
    } else if (ua.includes('Chrome/')) {
        browser = 'Chrome'
    } else if (ua.includes('Safari/')) {
        browser = 'Safari'
    }

    if (ua.includes('Windows')) {
        os = 'Windows'
    } else if (ua.includes('Mac OS')) {
        os = 'macOS'
    } else if (ua.includes('Android')) {
        os = 'Android'
    } else if (ua.includes('Linux')) {
        os = 'Linux'
    } else if (ua.includes('iPhone') || ua.includes('iPad')) {
        os = 'iOS'
    }

    return `${browser} on ${os}`
}

/**
 * Ensures a certificate credential exists for the current user, reusing
 * an existing one from IndexedDB if possible, or issuing a new one.
 */
export async function ensureCertificateCredential (): Promise<CertificateCredentialResult> {
    const creds = await api.getMyCredentials()
    const localKeys = await getAllCertificateKeys()
    const localKeyMap = new Map<string, StoredCertificateKey>(
        localKeys.map(k => [k.credentialId, k]),
    )

    // Try to find an existing server-side cert with a local private key
    for (const cert of creds.certificates) {
        const local = localKeyMap.get(cert.id)
        if (local) {
            return {
                certificatePem: local.certificatePem,
                privateKeyPem: local.privateKeyPem,
            }
        }
    }

    // No match found — issue a new certificate
    const { publicKeyPem, privateKeyPem } = await generateKeyPair()

    const result = await api.issueMyCertificate({
        issueCertificateCredentialRequest: {
            label: `Auto — ${getBrowserLabel()}`,
            publicKeyPem,
        },
    })

    await saveCertificateKey({
        credentialId: result.credential.id,
        privateKeyPem,
        certificatePem: result.certificatePem,
    })

    return {
        certificatePem: result.certificatePem,
        privateKeyPem,
    }
}

export async function loadCertificatesWithKeyStatus (): Promise<CertificateWithKeyStatus[]> {
    const creds = await api.getMyCredentials()
    const localKeys = await getAllCertificateKeys()
    const localKeySet = new Set(localKeys.map(k => k.credentialId))

    return creds.certificates.map(cert => ({
        credential: cert,
        hasLocalKey: localKeySet.has(cert.id),
    }))
}

export async function getLocalCertificate (credentialId: string): Promise<CertificateCredentialResult | null> {
    const local = await getCertificateKey(credentialId)
    if (!local) {
        return null
    }
    return {
        certificatePem: local.certificatePem,
        privateKeyPem: local.privateKeyPem,
    }
}
