// Package canonicaljson implements the RFC 8785 JSON Canonicalization Scheme
// used by tplater's signed and integrity-protected wire contracts.
package canonicaljson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// Canonical returns the RFC 8785 representation of v.
func Canonical(v any) ([]byte, error) {
	if err := validateUTF8(reflect.ValueOf(v), "document", make(map[visit]bool)); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("canonicaljson: marshal: %w", err)
	}
	return Canonicalize(raw)
}

type visit struct {
	typ  reflect.Type
	ptr  uintptr
	len  int
	kind reflect.Kind
}

const maxUTF8WalkDepth = 1024

func validateUTF8(value reflect.Value, path string, active map[visit]bool) error {
	return validateUTF8Depth(value, path, active, 0)
}

func validateUTF8Depth(value reflect.Value, path string, active map[visit]bool, depth int) error {
	if depth > maxUTF8WalkDepth {
		return errors.New("canonicaljson: value graph exceeds traversal depth")
	}
	if !value.IsValid() {
		return nil
	}
	for value.Kind() == reflect.Interface || value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return nil
		}
		if value.Kind() == reflect.Pointer {
			key := visit{typ: value.Type(), ptr: value.Pointer(), kind: value.Kind()}
			if active[key] {
				return errors.New("canonicaljson: cyclic value graph")
			}
			active[key] = true
			defer delete(active, key)
		}
		value = value.Elem()
	}
	switch value.Kind() {
	case reflect.String:
		if !utf8.ValidString(value.String()) {
			return fmt.Errorf("canonicaljson: invalid UTF-8 in %s", path)
		}
	case reflect.Map:
		if value.IsNil() {
			return nil
		}
		key := visit{typ: value.Type(), ptr: uintptr(value.UnsafePointer()), kind: value.Kind()}
		if active[key] {
			return errors.New("canonicaljson: cyclic value graph")
		}
		active[key] = true
		defer delete(active, key)
		iter := value.MapRange()
		for iter.Next() {
			key := iter.Key()
			if key.Kind() == reflect.String && !utf8.ValidString(key.String()) {
				return fmt.Errorf("canonicaljson: invalid UTF-8 in %s key", path)
			}
			if err := validateUTF8Depth(iter.Value(), path+".value", active, depth+1); err != nil {
				return err
			}
		}
	case reflect.Struct:
		for i := 0; i < value.NumField(); i++ {
			field := value.Type().Field(i)
			if field.PkgPath != "" || field.Tag.Get("json") == "-" {
				continue
			}
			if err := validateUTF8Depth(value.Field(i), path+"."+field.Name, active, depth+1); err != nil {
				return err
			}
		}
	case reflect.Array, reflect.Slice:
		if value.Kind() == reflect.Slice && value.IsNil() {
			return nil
		}
		var key visit
		if value.Kind() == reflect.Slice {
			key = visit{typ: value.Type(), ptr: value.Pointer(), len: value.Len(), kind: value.Kind()}
			if key.ptr != 0 {
				if active[key] {
					return errors.New("canonicaljson: cyclic value graph")
				}
				active[key] = true
				defer delete(active, key)
			}
		}
		for i := 0; i < value.Len(); i++ {
			if err := validateUTF8Depth(value.Index(i), fmt.Sprintf("%s[%d]", path, i), active, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

// Canonicalize parses one JSON value, rejects duplicate object names, and
// returns its RFC 8785 representation.
func Canonicalize(raw []byte) ([]byte, error) {
	v, err := parse(raw, true)
	if err != nil {
		return nil, err
	}
	return encode(v)
}

// DecodeStrict decodes one closed JSON wire value. It rejects invalid UTF-8,
// nulls, duplicate names, non-canonical key casing, and unknown fields.
func DecodeStrict(raw []byte, dst any) error {
	rv := reflect.ValueOf(dst)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		return errors.New("canonicaljson: destination must be a non-nil pointer")
	}
	v, err := parse(raw, false)
	if err != nil {
		return err
	}
	if err := validateShape(v, rv.Elem().Type(), "document"); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("canonicaljson: decode: %w", err)
	}
	if err := expectEOF(dec); err != nil {
		return err
	}
	return nil
}

func parse(raw []byte, allowNull bool) (any, error) {
	if !utf8.Valid(raw) {
		return nil, errors.New("canonicaljson: input is not valid UTF-8")
	}
	if err := rejectLoneSurrogates(raw); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	v, err := parseValue(dec, allowNull, "document")
	if err != nil {
		return nil, err
	}
	if err := expectEOF(dec); err != nil {
		return nil, err
	}
	return v, nil
}

func rejectLoneSurrogates(raw []byte) error {
	inString := false
	for i := 0; i < len(raw); i++ {
		switch raw[i] {
		case '"':
			inString = !inString
		case '\\':
			if !inString || i+1 >= len(raw) {
				continue
			}
			i++
			if raw[i] != 'u' || i+4 >= len(raw) {
				continue
			}
			code, err := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
			if err != nil {
				continue // The JSON decoder reports malformed escapes.
			}
			i += 4
			switch {
			case code >= 0xd800 && code <= 0xdbff:
				if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
					return errors.New("canonicaljson: lone high surrogate")
				}
				low, err := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
				if err != nil || low < 0xdc00 || low > 0xdfff {
					return errors.New("canonicaljson: invalid surrogate pair")
				}
				i += 6
			case code >= 0xdc00 && code <= 0xdfff:
				return errors.New("canonicaljson: lone low surrogate")
			}
		}
	}
	return nil
}

func parseValue(dec *json.Decoder, allowNull bool, path string) (any, error) {
	token, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("canonicaljson: parse %s: %w", path, err)
	}
	switch value := token.(type) {
	case json.Delim:
		switch value {
		case '{':
			object := make(map[string]any)
			for dec.More() {
				nameToken, err := dec.Token()
				if err != nil {
					return nil, fmt.Errorf("canonicaljson: parse %s name: %w", path, err)
				}
				name, ok := nameToken.(string)
				if !ok {
					return nil, fmt.Errorf("canonicaljson: non-string object name in %s", path)
				}
				if _, exists := object[name]; exists {
					return nil, fmt.Errorf("canonicaljson: duplicate object name %q in %s", name, path)
				}
				child, err := parseValue(dec, allowNull, path+"."+name)
				if err != nil {
					return nil, err
				}
				object[name] = child
			}
			end, err := dec.Token()
			if err != nil || end != json.Delim('}') {
				return nil, fmt.Errorf("canonicaljson: unterminated object in %s", path)
			}
			return object, nil
		case '[':
			array := make([]any, 0)
			for i := 0; dec.More(); i++ {
				child, err := parseValue(dec, allowNull, fmt.Sprintf("%s[%d]", path, i))
				if err != nil {
					return nil, err
				}
				array = append(array, child)
			}
			end, err := dec.Token()
			if err != nil || end != json.Delim(']') {
				return nil, fmt.Errorf("canonicaljson: unterminated array in %s", path)
			}
			return array, nil
		default:
			return nil, fmt.Errorf("canonicaljson: unexpected delimiter %q in %s", value, path)
		}
	case nil:
		if !allowNull {
			return nil, fmt.Errorf("canonicaljson: null is not allowed in %s", path)
		}
		return nil, nil
	case string, bool, json.Number:
		return value, nil
	default:
		return nil, fmt.Errorf("canonicaljson: unsupported token %T in %s", token, path)
	}
}

func expectEOF(dec *json.Decoder) error {
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("canonicaljson: multiple JSON values")
		}
		return fmt.Errorf("canonicaljson: trailing JSON: %w", err)
	}
	return nil
}

func validateShape(value any, typ reflect.Type, path string) error {
	// json.RawMessage is an intentionally opaque, already-parsed JSON value.
	// Its underlying representation is []byte, but treating it as a JSON array
	// makes valid embedded objects fail shape validation. The document parser
	// above has already rejected nulls, duplicate keys, invalid UTF-8 and
	// trailing values before this function is called.
	if typ == reflect.TypeOf(json.RawMessage{}) {
		return nil
	}
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	switch typ.Kind() {
	case reflect.Struct:
		object, ok := value.(map[string]any)
		if !ok {
			return fmt.Errorf("canonicaljson: %s must be an object", path)
		}
		fields := make(map[string]reflect.Type)
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			if field.PkgPath != "" {
				continue
			}
			name := strings.Split(field.Tag.Get("json"), ",")[0]
			if name == "-" {
				continue
			}
			if name == "" {
				name = field.Name
			}
			fields[name] = field.Type
		}
		for name, child := range object {
			fieldType, ok := fields[name]
			if !ok {
				return fmt.Errorf("canonicaljson: unknown or non-canonical field %q in %s", name, path)
			}
			if err := validateShape(child, fieldType, path+"."+name); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		array, ok := value.([]any)
		if !ok {
			return fmt.Errorf("canonicaljson: %s must be an array", path)
		}
		for i, child := range array {
			if err := validateShape(child, typ.Elem(), fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	case reflect.Map:
		object, ok := value.(map[string]any)
		if !ok || typ.Key().Kind() != reflect.String {
			return fmt.Errorf("canonicaljson: %s must be a string-keyed object", path)
		}
		for name, child := range object {
			if err := validateShape(child, typ.Elem(), path+"."+name); err != nil {
				return err
			}
		}
	}
	return nil
}

func encode(v any) ([]byte, error) {
	switch value := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(value))
		for key := range value {
			keys = append(keys, key)
		}
		sort.Slice(keys, func(i, j int) bool { return utf16Less(keys[i], keys[j]) })
		var out bytes.Buffer
		out.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				out.WriteByte(',')
			}
			writeString(&out, key)
			out.WriteByte(':')
			encoded, err := encode(value[key])
			if err != nil {
				return nil, err
			}
			out.Write(encoded)
		}
		out.WriteByte('}')
		return out.Bytes(), nil
	case []any:
		var out bytes.Buffer
		out.WriteByte('[')
		for i, child := range value {
			if i > 0 {
				out.WriteByte(',')
			}
			encoded, err := encode(child)
			if err != nil {
				return nil, err
			}
			out.Write(encoded)
		}
		out.WriteByte(']')
		return out.Bytes(), nil
	case json.Number:
		return canonicalNumber(value)
	case string:
		var out bytes.Buffer
		writeString(&out, value)
		return out.Bytes(), nil
	case bool, nil:
		return json.Marshal(value)
	default:
		return nil, fmt.Errorf("canonicaljson: unsupported value %T", v)
	}
}

func canonicalNumber(number json.Number) ([]byte, error) {
	f, err := strconv.ParseFloat(number.String(), 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
		return nil, fmt.Errorf("canonicaljson: invalid number %q", number)
	}
	if f == 0 {
		return []byte("0"), nil
	}
	abs := math.Abs(f)
	if abs >= 1e-6 && abs < 1e21 {
		return []byte(strconv.FormatFloat(f, 'f', -1, 64)), nil
	}
	s := strconv.FormatFloat(f, 'e', -1, 64)
	mantissa, exponent, ok := strings.Cut(s, "e")
	if !ok {
		return nil, fmt.Errorf("canonicaljson: invalid scientific number %q", s)
	}
	e, err := strconv.Atoi(exponent)
	if err != nil {
		return nil, fmt.Errorf("canonicaljson: invalid exponent: %w", err)
	}
	return []byte(mantissa + "e" + fmt.Sprintf("%+d", e)), nil
}

func utf16Less(a, b string) bool {
	aa, bb := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(aa) && i < len(bb); i++ {
		if aa[i] != bb[i] {
			return aa[i] < bb[i]
		}
	}
	return len(aa) < len(bb)
}

func writeString(out *bytes.Buffer, value string) {
	out.WriteByte('"')
	for len(value) > 0 {
		r, width := utf8.DecodeRuneInString(value)
		switch r {
		case '"':
			out.WriteString(`\"`)
		case '\\':
			out.WriteString(`\\`)
		case '\b':
			out.WriteString(`\b`)
		case '\t':
			out.WriteString(`\t`)
		case '\n':
			out.WriteString(`\n`)
		case '\f':
			out.WriteString(`\f`)
		case '\r':
			out.WriteString(`\r`)
		default:
			if r < 0x20 {
				fmt.Fprintf(out, `\u%04x`, r)
			} else {
				out.WriteRune(r)
			}
		}
		value = value[width:]
	}
	out.WriteByte('"')
}
