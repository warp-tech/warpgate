import { TargetKind } from 'gateway/lib/api'

export const TARGET_KIND_LABELS: Record<TargetKind, string> = {
    [TargetKind.Ssh]: 'SSH',
    [TargetKind.Http]: 'HTTP',
    [TargetKind.MySql]: 'MySQL',
    [TargetKind.Postgres]: 'PostgreSQL',
    [TargetKind.Kubernetes]: 'Kubernetes',
    [TargetKind.Vnc]: 'VNC',
    [TargetKind.Rdp]: 'RDP',
}
