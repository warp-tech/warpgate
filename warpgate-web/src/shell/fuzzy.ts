/**
 * Subsequence fuzzy matcher for the command palette.
 *
 * Hand-rolled rather than pulling in fuse.js or similar: the whole thing is
 * ~60 lines, and the alternative adds 20-plus KB to an air-gapped bundle to
 * rank at most a few hundred targets, users and sessions.
 *
 * Scoring favours the things an operator is actually reaching for:
 *   - a match at a word boundary beats one mid-token, so "pb" finds
 *     "prod-bastion" ahead of "superb-lab"
 *   - consecutive characters beat scattered ones, so "bast" prefers
 *     "bastion" over "b...a...s...t"
 *   - a prefix match on the whole string outranks everything
 *   - shorter haystacks win ties, because a query is more likely aimed at
 *     "web" than at "web-frontend-staging-replica"
 *
 * Hostnames and usernames are full of `-`, `.`, `_` and `:`, so those count as
 * word boundaries alongside case transitions.
 */

export interface FuzzyMatch {
    score: number
    /** Indices into the haystack that matched, for highlighting. */
    indices: number[]
}

const BOUNDARY = /[\s\-_./:@]/

function isBoundaryAt(text: string, index: number): boolean {
    if (index === 0) {
        return true
    }
    const prev = text[index - 1]
    const here = text[index]
    if (prev && BOUNDARY.test(prev)) {
        return true
    }
    // camelCase / PascalCase transition
    return (
        !!prev &&
        !!here &&
        prev === prev.toLowerCase() &&
        here === here.toUpperCase()
    )
}

const SCORE_BOUNDARY = 12
const SCORE_CONSECUTIVE = 8
const SCORE_BASE = 1
const PENALTY_DISTANCE = 1
const MAX_DISTANCE_PENALTY = 6

/**
 * Returns null when `query` is not a subsequence of `haystack`.
 * An empty query matches everything with score 0, so an unfiltered palette
 * still renders in its natural order.
 */
export function fuzzyMatch(query: string, haystack: string): FuzzyMatch | null {
    if (!query) {
        return { score: 0, indices: [] }
    }

    const q = query.toLowerCase()
    const h = haystack.toLowerCase()

    // Cheap exits that also produce the strongest scores.
    if (h === q) {
        return { score: 1000, indices: [...Array(haystack.length).keys()] }
    }
    if (h.startsWith(q)) {
        return {
            score: 500 + (100 - Math.min(haystack.length, 100)),
            indices: [...Array(q.length).keys()],
        }
    }

    const indices: number[] = []
    let score = 0
    let hi = 0
    let lastMatch = -1

    for (let qi = 0; qi < q.length; qi++) {
        const ch = q[qi]
        let found = -1
        while (hi < h.length) {
            if (h[hi] === ch) {
                found = hi
                break
            }
            hi++
        }
        if (found === -1) {
            return null
        }

        let charScore = SCORE_BASE
        if (isBoundaryAt(haystack, found)) {
            charScore += SCORE_BOUNDARY
        }
        if (found === lastMatch + 1) {
            charScore += SCORE_CONSECUTIVE
        } else if (lastMatch >= 0) {
            charScore -= Math.min(
                (found - lastMatch - 1) * PENALTY_DISTANCE,
                MAX_DISTANCE_PENALTY,
            )
        }

        score += charScore
        indices.push(found)
        lastMatch = found
        hi = found + 1
    }

    // Shorter haystacks win ties.
    score += Math.max(0, 40 - haystack.length) / 10
    return { score, indices }
}

export interface Scored<T> {
    item: T
    score: number
    indices: number[]
}

/**
 * Ranks `items` against `query` using the best-scoring of each item's
 * searchable strings. Items that match nothing are dropped.
 */
export function fuzzyRank<T>(
    query: string,
    items: T[],
    keys: (item: T) => string[],
    limit = 50,
): Scored<T>[] {
    const out: Scored<T>[] = []
    for (const item of items) {
        let best: FuzzyMatch | null = null
        let bestIndex = 0
        const fields = keys(item)
        for (let i = 0; i < fields.length; i++) {
            const field = fields[i]
            if (!field) {
                continue
            }
            const m = fuzzyMatch(query, field)
            if (m && (!best || m.score > best.score)) {
                best = m
                bestIndex = i
            }
        }
        if (best) {
            // Later fields are secondary (a description, an address), so a hit
            // there should not outrank a hit on the primary name.
            const demotion = bestIndex * 15
            out.push({
                item,
                score: best.score - demotion,
                indices: bestIndex === 0 ? best.indices : [],
            })
        }
    }
    out.sort((a, b) => b.score - a.score)
    return out.slice(0, limit)
}

/** Splits a string into matched/unmatched runs for highlight rendering. */
export function highlightRuns(
    text: string,
    indices: number[],
): { text: string; match: boolean }[] {
    if (!indices.length) {
        return [{ text, match: false }]
    }
    const set = new Set(indices)
    const runs: { text: string; match: boolean }[] = []
    let current = ''
    let currentMatch = set.has(0)

    for (let i = 0; i < text.length; i++) {
        const isMatch = set.has(i)
        if (isMatch !== currentMatch) {
            if (current) {
                runs.push({ text: current, match: currentMatch })
            }
            current = ''
            currentMatch = isMatch
        }
        current += text[i]
    }
    if (current) {
        runs.push({ text: current, match: currentMatch })
    }
    return runs
}
