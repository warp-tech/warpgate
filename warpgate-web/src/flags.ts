/**
 * Build-time feature flags.
 *
 * `import.meta.env.VITE_*` is **statically replaced by Vite at build time**,
 * not read at runtime. Verified by building twice: with the flag unset the
 * output contains the else-branch and zero occurrences of the expression
 * itself; with it set, the other branch is eliminated.
 *
 * The consequence matters operationally: a shipped Warpgate binary contains
 * exactly one UI, and rolling back means rebuilding and redeploying, not
 * flipping an environment variable on a running instance.
 *
 * A runtime flag would have to arrive through Warpgate's config and be
 * surfaced on the `Info` API response, which means a new Rust field — outside
 * this redesign's remit. Build-time is the right trade here, but it is a
 * trade, not a free switch.
 *
 * Usage:  VITE_NEW_UI=true npm run build
 */

export const NEW_UI = import.meta.env.VITE_NEW_UI === 'true'
