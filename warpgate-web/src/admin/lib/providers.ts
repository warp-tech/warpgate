/// The provider that owns rows synced from GitOps; other providers are shown by ID
const GITOPS = '00000000-0000-0000-0000-000000000000'

export function providerLabel(provider: string): string {
    return provider === GITOPS ? 'GitOps' : `provider ${provider}`
}
