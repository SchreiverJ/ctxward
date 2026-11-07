package vault

import (
	"bufio"
	"errors"
	"io"
)

// MaxLine is the longest line Filter will process. A longer line has no safe
// place to cut it (a secret could straddle the cut), so Filter stops instead.
const MaxLine = 1 << 20

// ErrLineTooLong is returned by Filter for a line over MaxLine.
var ErrLineTooLong = errors.New("line too long to filter")

// Filter copies r to w one line at a time, hiding secrets in each line, and
// flushes after every line so a long-running command stays live. On any error
// nothing unredacted has been written. Values that span lines are caught
// because each of their lines is also searched for (see valueTerms).
func (v *Vault) Filter(r io.Reader, w io.Writer) error {
	in := bufio.NewReaderSize(r, 64<<10)
	out := bufio.NewWriter(w)
	var line []byte
	for {
		chunk, err := in.ReadSlice('\n')
		line = append(line, chunk...)
		if len(line) > MaxLine {
			return ErrLineTooLong
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if len(line) > 0 {
			text, _ := v.Redact(string(line))
			if _, werr := out.WriteString(text); werr != nil {
				return werr
			}
			if werr := out.Flush(); werr != nil {
				return werr
			}
			line = line[:0]
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}
