// eslint-disable-next-line @typescript-eslint/explicit-module-boundary-types
export function toClassName(value: any) {
    let result = ''

    if (typeof value === 'string' || typeof value === 'number') {
        result += value
    } else if (typeof value === 'object') {
        if (Array.isArray(value)) {
            result = value.map(toClassName).filter(Boolean).join(' ')
        } else {
            for (const key in value) {
                if (value[key]) {
                    // eslint-disable-next-line @typescript-eslint/no-unused-expressions
                    result && (result += ' ')
                    result += key
                }
            }
        }
    }

    return result
}

// eslint-disable-next-line @typescript-eslint/explicit-module-boundary-types
export const classnames = (...args: any[]) => args.map(toClassName).filter(Boolean).join(' ')
