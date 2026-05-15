export enum ConnectionState {
    Connecting = 'Connecting',
    Connected = 'Connected',
    Disconnected = 'Disconnected',
    Error = 'Error'
}

export interface ReconnectingWebSocketOptions {
    url: string
    onOpen: () => void
    onMessage: (data: string) => void
}

export class ReconnectingWebSocket {
    state = $state(ConnectionState.Connecting)
    attempt = $state(0)

    private socket: WebSocket | null = null
    private timer: ReturnType<typeof setTimeout> | null = null
    private closed = false
    private url: string
    private onOpen: () => void
    private onMessage: (data: string) => void
    private maxAttempts = 5

    constructor (opts: ReconnectingWebSocketOptions) {
        this.url = opts.url
        this.onOpen = opts.onOpen
        this.onMessage = opts.onMessage
    }

    connect (): void {
        if (this.closed) {
            return
        }
        this.socket = new WebSocket(this.url)

        this.socket.addEventListener('open', () => {
            this.attempt = 0
            this.state = ConnectionState.Connected
            this.onOpen()
        })

        this.socket.addEventListener('message', e => {
            this.onMessage(e.data as string)
        })

        this.socket.addEventListener('error', () => {
            this.state = ConnectionState.Error
        })

        this.socket.addEventListener('close', () => {
            if (this.closed) {
                this.state = ConnectionState.Disconnected
                return
            }
            this.scheduleReconnect()
        })
    }

    send (data: string): void {
        this.socket?.send(data)
    }

    close (): void {
        this.closed = true
        this.cancelTimer()
        this.socket?.close()
    }

    private scheduleReconnect () {
        if (this.attempt >= this.maxAttempts) {
            this.state = ConnectionState.Disconnected
            return
        }
        const delay = Math.min(1000 * 2 ** this.attempt, 30_000)
        this.attempt++
        this.state = ConnectionState.Connecting
        this.timer = setTimeout(() => {
            this.timer = null
            this.connect()
        }, delay)
    }

    private cancelTimer () {
        if (this.timer !== null) {
            clearTimeout(this.timer)
            this.timer = null
        }
    }
}
