/**
 * The async-action state machine, lifted verbatim from common/AsyncButton.svelte.
 *
 * Timings, transitions, re-entrancy guard, form-validation handshake and
 * size pinning are unchanged — only the chrome around them is new. The old
 * AsyncButton keeps working untouched until Phase 4 migrates its call sites.
 *
 * Why each piece exists:
 *   - the 500ms delay before the spinner stops fast actions flashing a
 *     spinner for one frame
 *   - the 1000ms hold on done/failed lets the operator actually see the
 *     outcome before the label returns
 *   - width AND height are pinned from the pre-click measurements so the
 *     button does not resize under the pointer when its label is swapped
 *     for an icon, which would move whatever sits next to it
 *   - clicks during progress are dropped rather than queued
 */

export enum AsyncState {
    Normal = 'n',
    Progress = 'p',
    ProgressWithSpinner = 'ps',
    Done = 'd',
    Failed = 'f',
}

const SPINNER_DELAY_MS = 500
const RESULT_HOLD_MS = 1000

export class AsyncAction {
    state = $state(AsyncState.Normal)
    lastWidth = $state(0)
    lastHeight = $state(0)

    get busy(): boolean {
        return (
            this.state === AsyncState.Progress ||
            this.state === AsyncState.ProgressWithSpinner
        )
    }

    /** min-width/min-height to pin the control at its pre-click size. */
    get sizeStyle(): string {
        return `min-width: ${this.lastWidth}px; min-height: ${this.lastHeight}px;`
    }

    /**
     * Runs `action`, driving the state machine. Returns early without running
     * anything if the host element sits in a form that fails validation.
     *
     * Rethrows whatever `action` threw, after recording the failure — callers
     * and error boundaries upstream still see it.
     */
    async run(
        element: HTMLElement | undefined,
        action: () => unknown | Promise<unknown>,
    ): Promise<void> {
        if (!element || this.busy) {
            return
        }

        const parentForm = element.closest<HTMLFormElement>('form')
        if (parentForm) {
            // `was-validated` is Bootstrap's; `wg-validated` is ours. Both are
            // set so a form built from either generation styles correctly
            // while the migration is in flight.
            parentForm.classList.add('was-validated', 'wg-validated')
            if (!parentForm.checkValidity()) {
                return
            }
        }

        this.lastWidth = element.offsetWidth
        this.lastHeight = element.offsetHeight
        this.state = AsyncState.Progress
        setTimeout(() => {
            if (this.state === AsyncState.Progress) {
                this.state = AsyncState.ProgressWithSpinner
            }
        }, SPINNER_DELAY_MS)

        try {
            await action()
            this.state = AsyncState.Done
        } catch (e) {
            this.state = AsyncState.Failed
            throw e
        } finally {
            setTimeout(() => {
                if (
                    this.state === AsyncState.Done ||
                    this.state === AsyncState.Failed
                ) {
                    this.state = AsyncState.Normal
                    this.lastWidth = 0
                    this.lastHeight = 0
                }
            }, RESULT_HOLD_MS)
        }
    }
}
