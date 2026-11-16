package javaanalysis

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"reflect"
)

// exactEncoding writes v in a form two values share only when they are equal: every field,
// exported or not, in declaration order; strings as their raw bytes, length-prefixed (class
// files hold modified UTF-8, which a text encoding would rewrite); nil apart from empty. A
// kind it does not know (a map, an interface, a func) is an error, never a partial encoding.
func exactEncoding(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := writeExact(&buf, reflect.ValueOf(v)); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeExact(buf *bytes.Buffer, v reflect.Value) error {
	putLen := func(n int) { _ = binary.Write(buf, binary.LittleEndian, uint64(n)) }
	switch v.Kind() {
	case reflect.String:
		putLen(v.Len())
		buf.WriteString(v.String())
	case reflect.Bool:
		if v.Bool() {
			buf.WriteByte(1)
		} else {
			buf.WriteByte(0)
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		_ = binary.Write(buf, binary.LittleEndian, v.Int())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		_ = binary.Write(buf, binary.LittleEndian, v.Uint())
	case reflect.Pointer:
		if v.IsNil() {
			buf.WriteByte(0)
			return nil
		}
		buf.WriteByte(1)
		return writeExact(buf, v.Elem())
	case reflect.Slice:
		if v.IsNil() {
			buf.WriteByte(0)
			return nil
		}
		buf.WriteByte(1)
		putLen(v.Len())
		for i := range v.Len() {
			if err := writeExact(buf, v.Index(i)); err != nil {
				return err
			}
		}
	case reflect.Struct:
		putLen(v.NumField())
		for i := range v.NumField() {
			if err := writeExact(buf, v.Field(i)); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("exact encoding: unsupported kind %s", v.Kind())
	}
	return nil
}
