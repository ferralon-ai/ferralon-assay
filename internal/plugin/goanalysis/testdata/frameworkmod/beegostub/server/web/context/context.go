// Package context mirrors the part of beego's request context a handler reads.
package context

// Context mirrors beego's context.Context.
type Context struct {
	Input *BeegoInput
}

// BeegoInput mirrors beego's context.BeegoInput.
type BeegoInput struct {
	RequestBody []byte
	params      map[string]string
}

// Query mirrors (*BeegoInput).Query.
func (i *BeegoInput) Query(key string) string { return i.params[key] }
