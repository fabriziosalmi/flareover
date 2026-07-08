// SPDX-License-Identifier: AGPL-3.0-only

package render

import (
	"fmt"
	"io"
	"time"
)

// Step states.
const (
	stPending = iota
	stRunning
	stOK
	stFail
)

type step struct {
	name   string
	state  int
	detail string
	dur    time.Duration
}

// Progress is a live phase tracker. On a terminal it redraws in place so the
// steps animate (spinner → ✓/✗); off a terminal it prints one line per
// transition, so logs and CI stay readable.
type Progress struct {
	w         io.Writer
	p         palette
	tty       bool
	steps     []*step
	drawn     int
	spinIdx   int
	start     time.Time
	stepStart time.Time
}

var spinner = []rune{'⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'}

// NewProgress builds a tracker over the named steps.
func NewProgress(w io.Writer, names []string, color, tty bool) *Progress {
	pr := &Progress{w: w, p: newPalette(color), tty: tty, start: nowOr()}
	for _, n := range names {
		pr.steps = append(pr.steps, &step{name: n})
	}
	if pr.tty {
		pr.redraw()
	}
	return pr
}

// Start marks step i running.
func (pr *Progress) Start(i int) {
	if i >= 0 && i < len(pr.steps) {
		pr.steps[i].state = stRunning
		pr.stepStart = nowOr()
	}
	if pr.tty {
		pr.redraw()
	}
}

// Done marks step i complete with a detail line.
func (pr *Progress) Done(i int, detail string) { pr.finish(i, stOK, detail) }

// Fail marks step i failed.
func (pr *Progress) Fail(i int, detail string) { pr.finish(i, stFail, detail) }

func (pr *Progress) finish(i, state int, detail string) {
	if i < 0 || i >= len(pr.steps) {
		return
	}
	s := pr.steps[i]
	s.state = state
	s.detail = detail
	s.dur = nowOr().Sub(pr.stepStart)
	if pr.tty {
		pr.redraw()
	} else {
		fmt.Fprintln(pr.w, pr.lineFor(s))
	}
}

// redraw repaints the whole block in place (terminal only).
func (pr *Progress) redraw() {
	if pr.drawn > 0 {
		fmt.Fprintf(pr.w, "\033[%dA", pr.drawn) // cursor up over the previous block
	}
	for _, s := range pr.steps {
		fmt.Fprintf(pr.w, "\033[2K%s\n", pr.lineFor(s)) // clear line, print
	}
	pr.drawn = len(pr.steps)
	pr.spinIdx++
}

// lineFor formats one step's line.
func (pr *Progress) lineFor(s *step) string {
	p := pr.p
	var mark, name string
	switch s.state {
	case stPending:
		mark, name = p.gray+"·"+p.reset, p.gray+s.name+p.reset
	case stRunning:
		mark, name = p.yellow+string(spinner[pr.spinIdx%len(spinner)])+p.reset, p.bold+s.name+p.reset
	case stOK:
		mark, name = p.green+"✓"+p.reset, s.name
	case stFail:
		mark, name = p.red+"✗"+p.reset, s.name
	}
	line := fmt.Sprintf("  %s %s", mark, name)
	if s.detail != "" {
		line += fmt.Sprintf("  %s%s%s", p.dim, s.detail, p.reset)
	}
	if s.dur > 0 {
		line += fmt.Sprintf(" %s(%s)%s", p.gray, s.dur.Round(time.Millisecond), p.reset)
	}
	return line
}

// PrintLine emits a free-standing line below the progress block (e.g. a summary
// or the guided next command).
func (pr *Progress) PrintLine(s string) { fmt.Fprintln(pr.w, s) }

// nowOr returns the current time (thin wrapper for clarity/testability).
func nowOr() time.Time { return time.Now() }
