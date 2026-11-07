package vault

// automaton is an Aho-Corasick matcher: it finds every occurrence of every
// term in one left-to-right pass over the text, however many terms there are.
//
// The transition table is dense but compact: bytes that appear in no term
// share class 0 (which always returns to the start), and the rest get a small
// column number, so a table row is as wide as the terms' alphabet (about 90
// for secrets), not 256. Failure transitions are folded into the table, so
// scanning is one lookup per byte.
type automaton struct {
	class [256]uint8 // byte -> column; 0 = byte occurs in no term
	width int        // columns per state
	next  []int32    // state*width + column -> state
	out   []int32    // state -> index of the term that ends here, or -1
	link  []int32    // state -> nearest shorter state that ends a term, or -1
	lens  []int      // term index -> length in bytes
}

func newAutomaton(terms []string) *automaton {
	a := &automaton{lens: make([]int, len(terms))}

	a.width = 1
	for _, t := range terms {
		for i := 0; i < len(t); i++ {
			if a.class[t[i]] == 0 {
				a.class[t[i]] = uint8(a.width)
				a.width++
			}
		}
	}

	size := 1 // at most one state per byte of every term, plus the start
	for _, t := range terms {
		size += len(t)
	}
	a.next = make([]int32, 0, size*a.width)
	a.out = make([]int32, 0, size)
	a.link = make([]int32, 0, size)
	a.addState() // state 0 is the start
	for ti, t := range terms {
		a.lens[ti] = len(t)
		s := int32(0)
		for i := 0; i < len(t); i++ {
			slot := int(s)*a.width + int(a.class[t[i]])
			if a.next[slot] == 0 {
				n := a.addState() // grows a.next, so call it before indexing
				a.next[slot] = n
			}
			s = a.next[slot]
		}
		a.out[s] = int32(ti)
	}

	// Breadth-first: a state's failure state is always shallower, so it is
	// finished before we need it.
	fail := make([]int32, len(a.out))
	var queue []int32
	for c := 1; c < a.width; c++ {
		if s := a.next[c]; s != 0 {
			queue = append(queue, s)
		}
	}
	for len(queue) > 0 {
		u := queue[0]
		queue = queue[1:]
		for c := 0; c < a.width; c++ {
			slot := int(u)*a.width + c
			fallback := a.next[int(fail[u])*a.width+c]
			v := a.next[slot]
			if v == 0 {
				a.next[slot] = fallback // fold the failure transition in
				continue
			}
			fail[v] = fallback
			a.link[v] = a.link[fallback]
			if a.out[fallback] >= 0 {
				a.link[v] = fallback
			}
			queue = append(queue, v)
		}
	}
	return a
}

func (a *automaton) addState() int32 {
	a.next = append(a.next, make([]int32, a.width)...)
	a.out = append(a.out, -1)
	a.link = append(a.link, -1)
	return int32(len(a.out) - 1)
}

// scan calls found for every occurrence of every term in text, as the byte
// range [start, end) and the term's index. Occurrences are reported in order
// of their end; for one end, longest first. found returns false to stop.
func (a *automaton) scan(text string, found func(start, end, term int) bool) {
	s := int32(0)
	for i := 0; i < len(text); i++ {
		s = a.next[int(s)*a.width+int(a.class[text[i]])]
		n := s
		if a.out[n] < 0 {
			n = a.link[n]
		}
		for ; n >= 0; n = a.link[n] {
			t := int(a.out[n])
			if !found(i+1-a.lens[t], i+1, t) {
				return
			}
		}
	}
}
