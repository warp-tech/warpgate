import { shellEscape } from 'gateway/lib/shellEscape'
import type { Info } from 'gateway/lib/api'
import { CredentialKind } from 'admin/lib/api'

export interface ConnectionOptions {
    targetName?: string
    username?: string
    serverInfo?: Info
    targetExternalHost?: string
    ticketSecret?: string
}

export function makeSSHUsername (opt: ConnectionOptions): string {
    if (opt.ticketSecret) {
        return `ticket-${opt.ticketSecret}`
    }
    return `${opt.username ?? 'username'}:${opt.targetName ?? 'target'}`
}

export function makeExampleSSHCommand (opt: ConnectionOptions): string {
    return shellEscape(['ssh', `${makeSSHUsername(opt)}@${opt.serverInfo?.externalHost ?? 'warpgate-host'}`, '-p', (opt.serverInfo?.ports.ssh ?? 'warpgate-ssh-port').toString()])
}

export function makeMySQLUsername (opt: ConnectionOptions): string {
    if (opt.ticketSecret) {
        return `ticket-${opt.ticketSecret}`
    }
    return `${opt.username ?? 'username'}#${opt.targetName ?? 'target'}`
}

export function makeExampleMySQLCommand (opt: ConnectionOptions): string {
    let cmd = shellEscape(['mysql', '-u', makeMySQLUsername(opt), '--host', opt.serverInfo?.externalHost ?? 'warpgate-host', '--port', (opt.serverInfo?.ports.mysql ?? 'warpgate-mysql-port').toString(), '--ssl'])
    if (!opt.ticketSecret) {
        cmd += ' -p'
    }
    return cmd
}

export function makeExampleMySQLURI (opt: ConnectionOptions): string {
    const pwSuffix = opt.ticketSecret ? '' : ':<password>'
    return `mysql://${makeMySQLUsername(opt)}${pwSuffix}@${opt.serverInfo?.externalHost ?? 'warpgate-host'}:${opt.serverInfo?.ports.mysql ?? 'warpgate-mysql-port'}?sslMode=required`
}

export const makePostgreSQLUsername = makeMySQLUsername

export function makeExamplePostgreSQLCommand (opt: ConnectionOptions): string {
    return shellEscape(['psql', '-U', makeMySQLUsername(opt), '--host', opt.serverInfo?.externalHost ?? 'warpgate-host', '--port', (opt.serverInfo?.ports.postgres ?? 'warpgate-postgres-port').toString(), '--password', 'database-name'])
}

export function makeExamplePostgreSQLURI (opt: ConnectionOptions): string {
    const pwSuffix = opt.ticketSecret ? '' : ':<password>'
    return `postgresql://${makePostgreSQLUsername(opt)}${pwSuffix}@${opt.serverInfo?.externalHost ?? 'warpgate-host'}:${opt.serverInfo?.ports.postgres ?? 'warpgate-postgres-port'}/database-name?sslmode=require`
}

export function makeTargetURL (opt: ConnectionOptions): string {
    const host = opt.targetExternalHost ? `${opt.targetExternalHost}:${opt.serverInfo?.ports.http ?? 443}` : location.host
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

export function makeKubernetesNamespace (opt: ConnectionOptions): string {
    return 'default'
}

export function makeKubernetesClusterUrl (opt: ConnectionOptions): string {
    const baseUrl = `https://${opt.serverInfo?.externalHost ?? 'warpgate-host'}:${opt.serverInfo?.ports.kubernetes ?? 'warpgate-kubernetes-port'}`
    return `${baseUrl}/${opt.targetName ?? 'target'}`
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
    client-certificate-data: <your-client-certificate-base64>
    client-key-data: <your-private-key-base64>
`
    }
}

export function makeExampleKubectlCommand (opt: ConnectionOptions): string {
    return shellEscape(['kubectl', '--kubeconfig', 'warpgate-kubeconfig.yaml', 'get', 'pods'])
}
