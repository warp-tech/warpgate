import { api, TlsMode, type TestLdapServerRequest, type TestLdapServerResponse } from 'admin/lib/api'

export async function testLdapConnection(options: TestLdapServerRequest): Promise<TestLdapServerResponse> {
    const timeoutPromise = new Promise((_, reject) => {
        setTimeout(() => reject(new Error('Connection test timed out after 10 seconds')), 10000)
    })

    const testPromise = api.testLdapServerConnection({
        testLdapServerRequest: options,
    })

    return (await Promise.race([testPromise, timeoutPromise])) as TestLdapServerResponse
}

export function defaultLdapPortForTlsMode(tlsMode: TlsMode): number {
    if (tlsMode === TlsMode.Disabled) {
        return 389
    } else {
        return 636
    }
}
