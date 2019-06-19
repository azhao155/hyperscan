package secrule

import "fmt"

type object interface {
	ToString() string
}

type integerObject struct {
	Value int
}

func (i *integerObject) Incr(step int)    { i.Value += step }
func (i *integerObject) Decr(step int)    { i.Value -= step }
func (i *integerObject) ToString() string { return fmt.Sprintf("%d", i.Value) }

type stringObject struct {
	Value string
}

func (s *stringObject) ToString() string { return s.Value }
