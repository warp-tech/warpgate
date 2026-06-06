import { shellEscape } from 'gateway/lib/shellEscape'
import type { Info } from 'gateway/lib/api'
import { CredentialKind } from 'admin/lib/api'

export interface ConnectionOptions {
    targetName?: string
    username?: string
    serverInfo?: Info
    targetExternalHost?: string
    ticketSecret?: string
    targetDefaultDatabaseName?: string
    clientCertificatePem?: string
    clientPrivateKeyPem?: string
}

export function makeSSHUsername (opt: ConnectionOptions): string {
    if (opt.ticketSecret) {
        return `ticket-${opt.ticketSecret}`
    }
    return `${opt.username ?? 'username'}:${opt.targetName ?? 'target'}`
}

function protocolHost (opt: ConnectionOptions, protocol: 'ssh'|'http'|'mysql'|'postgres'|'kubernetes'): string {
    const globalHost = opt.serverInfo?.externalHost ?? 'warpgate-host'
    const hosts = opt.serverInfo?.externalHosts

    switch (protocol) {
        case 'ssh':
            return hosts?.ssh ?? globalHost
        case 'http':
            return hosts?.http ?? globalHost
        case 'mysql':
            return hosts?.mysql ?? globalHost
        case 'postgres':
            return hosts?.postgres ?? globalHost
        case 'kubernetes':
            return hosts?.kubernetes ?? globalHost
        default:
            return globalHost
    }
}

export function makeExampleSSHCommand (opt: ConnectionOptions): string {
    return shellEscape([
        'ssh',
        `${makeSSHUsername(opt)}@${protocolHost(opt, 'ssh')}`,
        '-p',
        (opt.serverInfo?.ports.ssh ?? 'warpgate-ssh-port').toString(),
    ])
}

export function makeExampleSCPCommand (opt: ConnectionOptions): string {
    return shellEscape([
        'scp',
        '-o',
        `User="${makeSSHUsername(opt)}"`,
        '-P',
        (opt.serverInfo?.ports.ssh ?? 'warpgate-ssh-port').toString(),
        'local-file',
        `${protocolHost(opt, 'ssh')}:remote-file`,
    ])
}

export function makeMySQLUsername (opt: ConnectionOptions): string {
    if (opt.ticketSecret) {
        return `ticket-${opt.ticketSecret}`
    }
    return `${opt.username ?? 'username'}#${opt.targetName ?? 'target'}`
}

export function makeExampleMySQLCommand (opt: ConnectionOptions): string {
    const dbName = opt.targetDefaultDatabaseName?.trim() || 'database-name'
    let cmd = shellEscape(['mysql', '-u', makeMySQLUsername(opt), '--host', protocolHost(opt, 'mysql'), '--port', (opt.serverInfo?.ports.mysql ?? 'warpgate-mysql-port').toString(), '--ssl', dbName])
    if (!opt.ticketSecret) {
        cmd += ' -p'
    }
    return cmd
}

export function makeExampleMySQLURI (opt: ConnectionOptions): string {
    const pwSuffix = opt.ticketSecret ? '' : ':<password>'
    const dbName = opt.targetDefaultDatabaseName?.trim() || 'database-name'
    return `mysql://${makeMySQLUsername(opt)}${pwSuffix}@${protocolHost(opt, 'mysql')}:${opt.serverInfo?.ports.mysql ?? 'warpgate-mysql-port'}/${dbName}?sslMode=required`
}

export const makePostgreSQLUsername = makeMySQLUsername

export function makeExamplePostgreSQLCommand (opt: ConnectionOptions): string {
    const dbName = opt.targetDefaultDatabaseName?.trim() || 'database-name'
    const args = ['psql', '-U', makeMySQLUsername(opt), '--host', protocolHost(opt, 'postgres'), '--port', (opt.serverInfo?.ports.postgres ?? 'warpgate-postgres-port').toString()]
    if (!opt.ticketSecret) {
        args.push('-W')
    }
    args.push(dbName)
    return shellEscape(args)
}

export function makeExamplePostgreSQLURI (opt: ConnectionOptions): string {
    const pwSuffix = opt.ticketSecret ? '' : ':<password>'
    const dbName = opt.targetDefaultDatabaseName?.trim() || 'database-name'
    return `postgresql://${makePostgreSQLUsername(opt)}${pwSuffix}@${protocolHost(opt, 'postgres')}:${opt.serverInfo?.ports.postgres ?? 'warpgate-postgres-port'}/${dbName}?sslmode=require`
}

export function makeTargetURL (opt: ConnectionOptions): string {
    const host = `${opt.targetExternalHost ?? protocolHost(opt, 'http')}:${opt.serverInfo?.ports.http ?? 443}`

    if (opt.ticketSecret) {
        return `${location.protocol}//${host}/?warpgate-ticket=${opt.ticketSecret}`
    }
    return `${location.protocol}//${host}/?warpgate-target=${opt.targetName}`
}

export const possibleCredentials: Record<string, Set<CredentialKind>> = {
    ssh: new Set([CredentialKind.Password, CredentialKind.PublicKey, CredentialKind.Totp, CredentialKind.WebUserApproval]),
    http: new Set([CredentialKind.Password, CredentialKind.Totp, CredentialKind.Sso]),
    mysql: new Set([CredentialKind.Password]),
    postgres: new Set([CredentialKind.Password, CredentialKind.WebUserApproval]),
    kubernetes: new Set([CredentialKind.Certificate, CredentialKind.WebUserApproval]),
}

export function abbreviatePublicKey (key: string): string {
    return key.slice(0, 16) + '...' + key.slice(-8)
}

export function makeKubernetesContext (opt: ConnectionOptions): string {
    if (opt.ticketSecret) {
        return `ticket-${opt.ticketSecret}`
    }
    return `${opt.username ?? 'username'}:${opt.targetName ?? 'target'}`
}

export function makeKubernetesNamespace (_opt: ConnectionOptions): string {
    return 'default'
}

export function makeKubernetesClusterUrl (opt: ConnectionOptions): string {
    const baseUrl = `https://${protocolHost(opt, 'kubernetes')}:${opt.serverInfo?.ports.kubernetes ?? 'warpgate-kubernetes-port'}`
    return `${baseUrl}/${encodeURIComponent(opt.targetName ?? 'target')}`
}

export function makeKubeconfig (opt: ConnectionOptions): string {
    const clusterUrl = makeKubernetesClusterUrl(opt)
    const context = makeKubernetesContext(opt)
    const namespace = makeKubernetesNamespace(opt)

    if (opt.ticketSecret) {
        // Token-based authentication using API ticket
        return `apiVersion: v1
kind: Config
clusters:
- cluster:
    server: ${clusterUrl}
    insecure-skip-tls-verify: true
  name: warpgate-${opt.targetName ?? 'target'}
contexts:
- context:
    cluster: warpgate-${opt.targetName ?? 'target'}
    namespace: ${namespace}
    user: ${context}
  name: ${context}
current-context: ${context}
users:
- name: ${context}
  user:
    token: ${opt.ticketSecret}
`
    } else {
        // Certificate-based authentication
        return `apiVersion: v1
kind: Config
clusters:
- cluster:
    server: ${clusterUrl}
    insecure-skip-tls-verify: true
  name: warpgate-${opt.targetName ?? 'target'}
contexts:
- context:
    cluster: warpgate-${opt.targetName ?? 'target'}
    namespace: ${namespace}
    user: ${context}
  name: ${context}
current-context: ${context}
users:
- name: ${context}
  user:
    client-certificate-data: ${opt.clientCertificatePem ? btoa(opt.clientCertificatePem) : '<your-client-certificate-base64>'}
    client-key-data: ${opt.clientPrivateKeyPem ? btoa(opt.clientPrivateKeyPem) : '<your-private-key-base64>'}
`
    }
}

export function makeExampleKubectlCommand (_opt: ConnectionOptions): string {
    return shellEscape(['kubectl', '--kubeconfig', 'warpgate-kubeconfig.yaml', 'get', 'pods'])
}


export interface ProtocolProperties {
    sessionsCanBeClosed: boolean
}

export const PROTOCOL_PROPERTIES: Record<string, ProtocolProperties> = {
    SSH: { sessionsCanBeClosed: true },
    HTTP: { sessionsCanBeClosed: true },
    MySQL: { sessionsCanBeClosed: true },
    PostgreSQL: { sessionsCanBeClosed: true },
    Kubernetes: { sessionsCanBeClosed: false },
}
