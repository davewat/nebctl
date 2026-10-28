// Package prompt asks questions on a terminal: free text with a default,
// yes/no, a numbered choice, and a pasted multi-line block.
package prompt

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// ErrClosed is returned when input ends before an answer arrives.
var ErrClosed = errors.New("input closed")

type Prompter struct {
	in  *bufio.Reader
	out io.Writer
}

func New(in io.Reader, out io.Writer) *Prompter {
	return &Prompter{in: bufio.NewReader(in), out: out}
}

func (p *Prompter) Printf(format string, a ...any) { fmt.Fprintf(p.out, format, a...) }
func (p *Prompter) Println(a ...any)               { fmt.Fprintln(p.out, a...) }
func (p *Prompter) Print(a ...any)                 { fmt.Fprint(p.out, a...) }

func (p *Prompter) line() (string, error) {
	s, err := p.in.ReadString('\n')
	if err != nil {
		if errors.Is(err, io.EOF) && s != "" {
			return strings.TrimSpace(s), nil
		}
		if errors.Is(err, io.EOF) {
			return "", ErrClosed
		}
		return "", err
	}
	return strings.TrimSpace(s), nil
}

// Ask returns the answer, or def when the answer is empty.
func (p *Prompter) Ask(q, def string) (string, error) {
	if def != "" {
		p.Printf("%s [%s]: ", q, def)
	} else {
		p.Printf("%s: ", q)
	}
	s, err := p.line()
	if err != nil {
		return "", err
	}
	if s == "" {
		return def, nil
	}
	return s, nil
}

// AskValid asks until valid accepts the answer. An empty answer with no
// default is passed to valid too, so valid decides whether blank is allowed.
func (p *Prompter) AskValid(q, def string, valid func(string) error) (string, error) {
	for {
		s, err := p.Ask(q, def)
		if err != nil {
			return "", err
		}
		if err := valid(s); err != nil {
			p.Printf("  %v\n", err)
			continue
		}
		return s, nil
	}
}

func (p *Prompter) Confirm(q string, def bool) (bool, error) {
	hint := "y/N"
	if def {
		hint = "Y/n"
	}
	for {
		p.Printf("%s [%s]: ", q, hint)
		s, err := p.line()
		if err != nil {
			return false, err
		}
		switch strings.ToLower(s) {
		case "":
			return def, nil
		case "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		}
		p.Println("  answer y or n")
	}
}

// Choose prints the options numbered from 1 and returns the chosen index.
func (p *Prompter) Choose(q string, options []string, def int) (int, error) {
	p.Println(q)
	for i, o := range options {
		p.Printf("  %d) %s\n", i+1, o)
	}
	for {
		s, err := p.Ask("Choose", strconv.Itoa(def+1))
		if err != nil {
			return 0, err
		}
		n, err := strconv.Atoi(s)
		if err == nil && n >= 1 && n <= len(options) {
			return n - 1, nil
		}
		p.Printf("  enter a number from 1 to %d\n", len(options))
	}
}

// Paste reads lines until one contains end, and returns them all.
func (p *Prompter) Paste(q, end string) (string, error) {
	p.Println(q)
	var b strings.Builder
	for {
		s, err := p.line()
		if err != nil {
			return "", err
		}
		b.WriteString(s)
		b.WriteByte('\n')
		if strings.Contains(s, end) {
			return b.String(), nil
		}
	}
}
