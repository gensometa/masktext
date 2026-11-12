package mask

import "regexp"

// Assignment values are parsed as shell words without evaluating any input.
// This also covers commented-out assignments and command substitutions.
var assignment = regexp.MustCompile(`(?m)(?:^|[ \t;])(?:#[ \t]*)?(?:(?:export|readonly|local|declare|typeset)[ \t]+(?:-[a-zA-Z]+[ \t]+)*)?[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]\r\n]+\])?\+?=`)

func shellAssignments(s string) []span {
	var spans []span
	covered := 0
	for _, loc := range assignment.FindAllStringIndex(s, -1) {
		if loc[1] <= covered {
			continue
		}
		start := loc[1]
		end := shellWordEnd(s, start)
		covered = end
		if end == start {
			continue
		}
		// Keep the outer quotes/backticks when the entire value is one quoted
		// expression, making the result easier to read. Mixed words are replaced whole.
		if end-start >= 2 && (s[start] == '\'' || s[start] == '"' || s[start] == '`') && s[end-1] == s[start] && quoteEnd(s, start) == end {
			start++
			end--
		}
		if end > start {
			spans = append(spans, span{start, end, "VARIABLE", -1})
		}
	}
	return spans
}

// quoteEnd returns the end of one quoted segment, or EOF for an unclosed quote.
func quoteEnd(s string, start int) int { return quoteEndDepth(s, start, 0) }

func quoteEndDepth(s string, start, depth int) int {
	if depth > 128 {
		return len(s)
	}
	quote := s[start]
	for i := start + 1; i < len(s); i++ {
		if s[i] == '\\' && quote != '\'' {
			i++
			continue
		}
		if quote == '"' && s[i] == '`' {
			i = quoteEndDepth(s, i, depth+1) - 1
			continue
		}
		if quote == '"' && s[i] == '$' && i+1 < len(s) && (s[i+1] == '(' || s[i+1] == '{') {
			i = groupEndDepth(s, i+1, depth+1) - 1
			continue
		}
		if s[i] == quote {
			return i + 1
		}
	}
	return len(s)
}

func groupEnd(s string, start int) int { return groupEndDepth(s, start, 0) }

func groupEndDepth(s string, start, depth int) int {
	if depth > 128 {
		return len(s)
	}
	close := byte(')')
	if s[start] == '{' {
		close = '}'
	}
	for i := start + 1; i < len(s); i++ {
		if s[i] == '\\' {
			i++
			continue
		}
		if s[i] == '\'' || s[i] == '"' || s[i] == '`' {
			i = quoteEndDepth(s, i, depth+1) - 1
			continue
		}
		if s[i] == '(' || s[i] == '{' {
			i = groupEndDepth(s, i, depth+1) - 1
			continue
		}
		if s[i] == close {
			return i + 1
		}
	}
	return len(s)
}

func shellWordEnd(s string, start int) int {
	for i := start; i < len(s); {
		c := s[i]
		if c == '\\' {
			if i+1 < len(s) {
				i += 2
			} else {
				i++
			}
			continue
		}
		if c == '\'' || c == '"' || c == '`' {
			i = quoteEnd(s, i)
			continue
		}
		if c == '(' {
			i = groupEnd(s, i)
			continue
		}
		if c == '$' && i+1 < len(s) && s[i+1] == '{' {
			i = groupEnd(s, i+1)
			continue
		}
		if c == ')' {
			return i
		}
		if c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == ';' || c == '|' || c == '&' || c == '<' || c == '>' {
			return i
		}
		i++
	}
	return len(s)
}
