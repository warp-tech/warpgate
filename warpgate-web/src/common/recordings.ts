import type { IconDefinition } from '@fortawesome/free-brands-svg-icons'
import {
    faArrowRightArrowLeft,
    faDesktop,
    faList,
    faSquare,
    faTerminal,
} from '@fortawesome/free-solid-svg-icons'
import type { Recording } from 'admin/lib/api'

export type RecordingMetadata =
    | {
          type: 'kubernetes-exec'
          namespace: string
          pod: string
          // Absent when the client named no container: kubectl omits it for
          // single-container pods and lets the API server choose.
          container?: string | null
          // Recordings written before argv was captured in full carry a bare
          // string here rather than the argv array.
          command: string | string[]
      }
    | {
          type: 'kubernetes-attach'
          namespace: string
          pod: string
          container?: string | null
      }
    | {
          type: 'kubernetes-api'
      }
    | {
          type: 'ssh-shell'
          channel: number
      }
    | {
          type: 'ssh-exec'
          channel: number
      }
    | {
          type: 'ssh-direct-tcpip'
          host: string
          port: number
      }
    | {
          type: 'ssh-direct-socket'
          path: string
      }
    | {
          type: 'ssh-forwarded-tcpip'
          host: string
          port: number
      }
    | {
          type: 'ssh-forwarded-socket'
          path: string
      }
    | {
          type: 'desktop'
          protocol: string
          target: string
      }

/** Older recordings stored a single string where argv is now an array. */
function formatCommand(command: string | string[]): string {
    return Array.isArray(command) ? command.join(' ') : command
}

export function recordingMetadataToFieldSet(
    metadata: RecordingMetadata,
): [string, string][] {
    const fieldSets: [string, string][] = []

    switch (metadata.type) {
        case 'kubernetes-exec':
            fieldSets.push(['Namespace', metadata.namespace])
            fieldSets.push(['Pod', metadata.pod])
            if (metadata.container) {
                fieldSets.push(['Container', metadata.container])
            }
            fieldSets.push(['Command', formatCommand(metadata.command)])
            break
        case 'kubernetes-attach':
            fieldSets.push(['Namespace', metadata.namespace])
            fieldSets.push(['Pod', metadata.pod])
            if (metadata.container) {
                fieldSets.push(['Container', metadata.container])
            }
            break
        case 'ssh-shell':
            fieldSets.push(['Channel', metadata.channel.toString()])
            break
        case 'ssh-exec':
            fieldSets.push(['Channel', metadata.channel.toString()])
            break
        case 'ssh-direct-tcpip':
        case 'ssh-forwarded-tcpip':
            fieldSets.push(['Host', metadata.host])
            fieldSets.push(['Port', metadata.port.toString()])
            break
        case 'ssh-direct-socket':
        case 'ssh-forwarded-socket':
            fieldSets.push(['Path', metadata.path])
            break
        case 'desktop':
            break
    }

    return fieldSets
}

export function recordingTypeLabel(recording: Recording): string {
    const metadata = JSON.parse(recording.metadata) as RecordingMetadata | null
    switch (metadata?.type) {
        case 'kubernetes-api':
            return 'API session'
        case 'kubernetes-exec':
            return 'Pod exec session'
        case 'kubernetes-attach':
            return 'Pod attach session'
        case 'ssh-shell':
            return 'Shell session'
        case 'ssh-exec':
            return 'SSH exec request'
        case 'ssh-direct-tcpip':
            return 'Local TCP forward'
        case 'ssh-direct-socket':
            return 'Local UNIX socket forward'
        case 'ssh-forwarded-tcpip':
            return 'Remote TCP forward'
        case 'ssh-forwarded-socket':
            return 'Remote UNIX socket forward'
        case 'desktop':
            return 'Desktop session'
    }

    return 'Unknown session type'
}

export function recordingTypeIcon(recording: Recording): IconDefinition {
    const metadata = JSON.parse(recording.metadata) as RecordingMetadata | null
    switch (metadata?.type) {
        case 'kubernetes-api':
            return faList
        case 'kubernetes-exec':
            return faTerminal
        case 'kubernetes-attach':
            return faTerminal
        case 'ssh-shell':
            return faTerminal
        case 'ssh-exec':
            return faTerminal
        case 'ssh-direct-tcpip':
            return faArrowRightArrowLeft
        case 'ssh-direct-socket':
            return faArrowRightArrowLeft
        case 'ssh-forwarded-tcpip':
            return faArrowRightArrowLeft
        case 'ssh-forwarded-socket':
            return faArrowRightArrowLeft
        case 'desktop':
            return faDesktop
    }

    return faSquare
}
