import type { TargetOptions } from './api'

type TargetKindName = TargetOptions['kind']
type OptionsOf<K extends TargetKindName> = Extract<TargetOptions, { kind: K }>
type PortKind = {
    [K in TargetKindName]: OptionsOf<K> extends { port: number } ? K : never
}[TargetKindName]

export const DEFAULT_PORTS: { [K in PortKind]: number } = {
    Ssh: 22,
    MySql: 3306,
    Postgres: 5432,
    Rdp: 3389,
    Vnc: 5900,
}

function hostPort({ kind, host, port }: OptionsOf<PortKind>): string {
    if (port === DEFAULT_PORTS[kind]) {
        return host
    }
    return host.includes(':') ? `[${host}]:${port}` : `${host}:${port}`
}

const ADDRESS: { [K in TargetKindName]: (_: OptionsOf<K>) => string } = {
    Ssh: hostPort,
    Http: o => o.url,
    MySql: hostPort,
    Postgres: hostPort,
    Kubernetes: o => o.clusterUrl,
    Rdp: hostPort,
    Vnc: hostPort,
}

export function targetAddress(options: TargetOptions): string {
    // TS can't correlate the indexed function with the narrowed argument.
    const format = ADDRESS[options.kind] as (_: TargetOptions) => string
    return format(options)
}
