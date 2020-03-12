package hyperscan

import (
	"bytes"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var removePcrePlusPossessiveQuantifierRegex = regexp.MustCompile(`((^|[^\\])(\\\\)*)\+\+`)
var removePcreStarPossessiveQuantifierRegex = regexp.MustCompile(`((^|[^\\])(\\\\)*)\*\+`)
var removePcreQuestionmarkPossessiveQuantifierRegex = regexp.MustCompile(`((^|[^\\])(\\\\)*)\?\+`)
var removePcreRangePossessiveQuantifierRegex = regexp.MustCompile(`((^|[^\\])(\\\\)*)({\d+(,(\d+)?)?})\+`)

// PCRE has the possessive quantifier "++", which is just meant as a hint to not backtrack and thereby increase performance.
// Go regexp does not need this, as it never backtracks anyway. The syntax is invalid in Go regexp. This function removes it from a regex.
func removePcrePossessiveQuantifier(r string) string {
	if strings.Index(r, "++") != -1 {
		r = removePcrePlusPossessiveQuantifierRegex.ReplaceAllString(r, "${1}+")
	}

	if strings.Index(r, "*+") != -1 {
		r = removePcreStarPossessiveQuantifierRegex.ReplaceAllString(r, "${1}*")
	}

	if strings.Index(r, "?+") != -1 {
		r = removePcreQuestionmarkPossessiveQuantifierRegex.ReplaceAllString(r, "${1}?")
	}

	if strings.Index(r, "}+") != -1 {
		r = removePcreRangePossessiveQuantifierRegex.ReplaceAllString(r, "${1}${4}")
	}

	return r
}

var endsWithWordBoundaryRegex = regexp.MustCompile(`(^|[^\\])(\\\\)*\\b$`)
var beginsWithWordCharRegex = regexp.MustCompile(`^\w`)

// regexWithBackref describes a regex which originally contained a backreference (such as `\1`), but has been modified to replace the backreference with the group it was referring to.
// It only supports backrefs to groups that are surrounded by word boundaries, such as `\b(x+)\b \b\1\b`, and the negative case, such as `\b(x+)\b (?!\b\1\b)(x+)`.
type regexWithBackref struct {
	newRegex                 string
	lookbehindReferenceToID  int
	shouldBeEqualGroupIDs    []int
	shouldBeNotEqualGroupIDs []int
}

func newRegexWithBackref(origRegex string) (
	hasBackref bool,
	r regexWithBackref,
	err error,
) {
	group0, err := parseRegex(removePcrePossessiveQuantifier(origRegex))
	if err != nil {
		return
	}

	// Determine which backref group we are dealing with.
	var maxIDSeen int
	var f func(g *rxGroup)
	f = func(g *rxGroup) {
		for i, p := range g.parts {
			switch p := p.(type) {

			case *rxBackref:
				hasBackref = true

				if r.lookbehindReferenceToID == 0 {
					r.lookbehindReferenceToID = p.referencedGroupIdx
				}

				if r.lookbehindReferenceToID != p.referencedGroupIdx {
					err = fmt.Errorf("backreferences to multiple different groups is not supported")
					return
				}

				if p.referencedGroupIdx > maxIDSeen {
					err = fmt.Errorf("backreference attempted to reference group %d, but only backreference to previous groups is supported", p.referencedGroupIdx)
					return
				}

				if p.referencedGroupIdx == g.ID {
					err = fmt.Errorf("backreference in group %d attempted to reference group %d, but circular backreferences are not support", g.ID, p.referencedGroupIdx)
					return
				}

				if p.referencedGroupIdx == 0 {
					err = fmt.Errorf("backreference to group 0 is not supported")
					return
				}

				if i == 0 || endsWithWordBoundaryRegex.FindString(g.parts[i-1].string()) == "" || i+1 > len(g.parts) || !strings.HasPrefix(g.parts[i+1].string(), `\b`) {
					err = fmt.Errorf(`only backreference that are surrounded by word boundaries (\b) are supported`)
					return
				}

			case *rxGroup:
				if p.ID > maxIDSeen {
					maxIDSeen = p.ID
				}

				f(p)
				if err != nil {
					return
				}

			}
		}
	}
	f(group0)

	if err != nil {
		return
	}

	if !hasBackref {
		return
	}

	// Save a pointer to the group which the backref is referring to.
	var backrefReferringTo *rxGroup
	f = func(g *rxGroup) {
		for i, p := range g.parts {
			switch p := p.(type) {

			case *rxGroup:
				if p.ID == r.lookbehindReferenceToID {
					if i == 0 || endsWithWordBoundaryRegex.FindString(g.parts[i-1].string()) == "" || i+1 > len(g.parts) || !strings.HasPrefix(g.parts[i+1].string(), `\b`) {
						err = fmt.Errorf(`only backreference to groups that are surrounded by word boundaries (\b) are supported`)
						return
					}

					backrefReferringTo = p
					return
				}

				f(p)
			}

			if backrefReferringTo != nil {
				return
			}
		}
	}
	f(group0)
	if err != nil {
		return
	}

	// Replace backref with the group it is referring to
	standInGroups := make(map[*rxGroup]bool)         // Groups that were created as stand-ins for where backrefs used to be.
	standInGroupsNegative := make(map[*rxGroup]bool) // Groups that were created as stand-ins for for example "(?!\1)(abc\d+)" in an expression like "(abc\d+)(?!\1)(abc\d+)"
	f = func(g *rxGroup) {
		for i, p := range g.parts {
			switch p := p.(type) {

			case *rxBackref:
				standInGroup := &rxGroup{
					parts: backrefReferringTo.parts,
				}
				g.parts[i] = standInGroup
				standInGroups[standInGroup] = true

			case *rxGroup:
				// This part handles the case when the regex is looking for "not equal to the backreference".
				// For example when CRS rule 942130 looks for "1 != 2".
				// This means we are looking here for patterns such as: (abc\d+)(?!\b\1\b)(abc\d+)
				// Is this a negative lookahead group just containing "?!" and "\b\1\b", and is there a sibling part to the right?
				if p.isNegativeLookahead && len(p.parts) == 3 && i+1 < len(g.parts) {
					backrefGroupContent := backrefReferringTo.string()

					// Is the backref wrapped in word boundaries?
					if !(p.parts[0].string() == `?!\b` && p.parts[2].string() == `\b`) {
						continue
					}

					// Is there a backreference, is it the right backreference, and does the sibling to the right correspond to the backreference group?
					b, curIsBackref := p.parts[1].(*rxBackref)
					_, nextIsGroup := g.parts[i+1].(*rxGroup)
					if curIsBackref && b.referencedGroupIdx == r.lookbehindReferenceToID && nextIsGroup && g.parts[i+1].string() == backrefGroupContent {
						standInGroup := &rxGroup{}
						standInGroup.parts = []rxPart{&rxText{text: `\b`}}
						standInGroup.parts = append(standInGroup.parts, backrefReferringTo.parts...)
						standInGroup.parts = append(standInGroup.parts, &rxText{text: `\b`})

						g.parts[i] = standInGroup
						standInGroupsNegative[standInGroup] = true
						g.parts[i+1] = &rxText{text: ""}
						continue
					}

					// Like above, but in case the sibling to the right is not a group
					nextTextPart, nextIsText := g.parts[i+1].(*rxText)
					backrefGroupContentNoParens := backrefGroupContent[1 : len(backrefGroupContent)-1]
					if curIsBackref && b.referencedGroupIdx == r.lookbehindReferenceToID && nextIsText && strings.HasPrefix(nextTextPart.string(), backrefGroupContentNoParens) {
						standInGroup := &rxGroup{}
						standInGroup.parts = []rxPart{&rxText{text: `\b`}}
						standInGroup.parts = append(standInGroup.parts, backrefReferringTo.parts...)
						standInGroup.parts = append(standInGroup.parts, &rxText{text: `\b`})

						g.parts[i] = standInGroup
						standInGroupsNegative[standInGroup] = true
						nextTextPart.text = strings.TrimPrefix(nextTextPart.text, backrefGroupContentNoParens)
						continue
					}
				}

				f(p)

			}
		}
	}
	f(group0)

	// Update group IDs
	nextID := 1
	f = func(g *rxGroup) {
		for _, p := range g.parts {
			switch p := p.(type) {

			case *rxGroup:
				if !p.isNonCapturing {
					p.ID = nextID
					nextID++

					if standInGroups[p] {
						r.shouldBeEqualGroupIDs = append(r.shouldBeEqualGroupIDs, p.ID)
					}

					if standInGroupsNegative[p] {
						r.shouldBeNotEqualGroupIDs = append(r.shouldBeNotEqualGroupIDs, p.ID)
					}
				}

				f(p)

			}
		}
	}
	f(group0)

	r.newRegex = group0.string()
	r.newRegex = r.newRegex[1 : len(r.newRegex)-1]
	return
}

func (r *regexWithBackref) tryMatch(input []byte, rx *goRegexpFacade) (data []byte, captureGroups [][]byte) {
	remainingInput := input

	for {
		locs := rx.FindAllSubmatchIndex(remainingInput, -1)
		if locs == nil {
			break
		}

		isMatch := true
		for _, loc := range locs {
			// The length of the second dimension will always an even number, because FindAllSubmatchIndex returns pairs of start-end-locations.
			var cg [][]byte
			for i := 0; i < len(loc); i = i + 2 {
				if loc[i] != -1 {
					cg = append(cg, remainingInput[loc[i]:loc[i+1]])
				} else {
					// This capture group was not found
					cg = append(cg, []byte{})
				}
			}

			// Check whether the backreference stand-in groups match the group they were referencing.
			for _, g := range r.shouldBeEqualGroupIDs {
				a := cg[r.lookbehindReferenceToID]
				b := cg[g]

				if len(b) == 0 {
					continue
				}

				if !bytes.EqualFold(a, b) {
					isMatch = false
				}
			}
			for _, g := range r.shouldBeNotEqualGroupIDs {
				a := cg[r.lookbehindReferenceToID]
				b := cg[g]

				if len(b) == 0 {
					continue
				}

				if bytes.EqualFold(a, b) {
					isMatch = false
				}
			}

			if isMatch {
				data = remainingInput[loc[0]:loc[1]]
				captureGroups = cg
				return
			}
		}

		// Cut off the beginning of the string at word boundaries, as there may be overlapping parts of the string that match the rewritten regex, but where the groups dont actually match.
		for {
			remainingInput = remainingInput[1:]

			if len(remainingInput) == 0 {
				return
			}

			if !beginsWithWordCharRegex.Match(remainingInput) {
				break
			}
		}

	}

	return
}

type rxPart interface {
	string() string
}

// rxGroup is a part of the regex delimited by parenthesis, e.g. "(def)" in "abc(def)+".
type rxGroup struct {
	parts               []rxPart
	isNonCapturing      bool
	isNegativeLookahead bool
	ID                  int
}

func (g *rxGroup) string() string {
	var b strings.Builder
	b.WriteRune('(')
	for _, part := range g.parts {
		b.WriteString(part.string())
	}
	b.WriteRune(')')
	return b.String()
}

// rxText is a part of the regex we will just store as is, because we are not interested in parsing it further, e.g. "abc+".
type rxText struct {
	text string
}

func (t *rxText) string() string {
	return t.text
}

// rxBackref is a backreference operator such as "\4".
type rxBackref struct {
	referencedGroupIdx int
}

func (b *rxBackref) string() string {
	return "\\" + strconv.Itoa(b.referencedGroupIdx)
}

func parseRegex(rx string) (group0 *rxGroup, err error) {
	var parts []rxPart
	escape := false
	charclass := false
	curTextStart := 0
	curGroupID := 0
	curGroup := &rxGroup{}
	var stack []*rxGroup

	for i, c := range rx {
		if escape {
			if '0' <= c && c <= '9' {
				// Append the text part we've just walked through.
				if i-1 > curTextStart {
					curGroup.parts = append(curGroup.parts, rxPart(&rxText{rx[curTextStart : i-1]}))
				}
				curTextStart = i + 1

				// Append the backref.
				groupIdx, _ := strconv.Atoi(string(c))
				curGroup.parts = append(curGroup.parts, &rxBackref{referencedGroupIdx: groupIdx})
			}

			escape = false
		} else if c == '\\' {
			escape = true
		} else if charclass {
			if c == ']' {
				charclass = false
			} else if c == '\\' {
				escape = true
			}
		} else if c == '[' {
			charclass = true
		} else if c == '(' || c == ')' {
			// Append the text part we've just walked through
			if i > curTextStart {
				curGroup.parts = append(curGroup.parts, rxPart(&rxText{rx[curTextStart:i]}))
			}
			curTextStart = i + 1

			if c == '(' {
				// Push current group and start a new group
				stack = append(stack, curGroup)
				curGroup = &rxGroup{}
				// Determine if this is a non-capturing group
				if i+1 < len(rx) && rx[i+1] == '?' {
					curGroup.isNonCapturing = true
					if i+2 < len(rx) && rx[i+2] == '!' {
						curGroup.isNegativeLookahead = true
					}
				} else {
					curGroupID++
					curGroup.ID = curGroupID
				}
			} else if c == ')' {
				if len(stack) == 0 {
					err = fmt.Errorf("unmatched parenthesis at character %d", i)
					return
				}

				// Pop and append the group we've just walked through
				prevGroup := curGroup
				curGroup, stack = stack[len(stack)-1], stack[:len(stack)-1]
				curGroup.parts = append(curGroup.parts, rxPart(prevGroup))
			}
		}
	}

	if len(stack) != 0 {
		err = fmt.Errorf("incomplete group")
		return
	}

	// Append the remaining text part we've just walked through
	if curTextStart < len(rx) {
		curGroup.parts = append(curGroup.parts, rxPart(&rxText{rx[curTextStart:]}))
	}
	parts = curGroup.parts

	group0 = &rxGroup{
		parts: parts,
	}

	return
}
