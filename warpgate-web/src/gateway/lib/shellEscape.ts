import { UAParser } from 'ua-parser-js'

function escapeUnix (arg: string): string {
    if (!/^[A-Za-z0-9_/-]+$/.test(arg)) {
        return ('\'' + arg.replace(/'/g, '\'"\'"\'') + '\'').replace(/''/g, '')
    }
    return arg
}

function escapeWin (arg: string): string {
    if (!/^[A-Za-z0-9_/-]+$/.test(arg)) {
        return '"' + arg.replace(/"/g, '""') + '"'
    }
    return arg
}

const isWin = new UAParser().getOS().name === 'Windows'

export function shellEscape (stringOrArray: string[]|string): string {
    const ret: string[] = []

    const escapePath = isWin ? escapeWin : escapeUnix

    if (typeof stringOrArray == 'string') {
        return escapePath(stringOrArray)
    } else {
        stringOrArray.forEach(function (member) {
            ret.push(escapePath(member))
        })
        return ret.join(' ')
    }
}
