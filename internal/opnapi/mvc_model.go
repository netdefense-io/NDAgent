package opnapi

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// EntityModel is one OPNsense MVC entity as the device defines it, read from
// the entity's template: its get<Entity> call without a uuid answers every
// field of the model with its default.
//
// The field set comes from the device on purpose. A list kept here would drop
// whatever a release adds and send what a release removed, and OPNsense's
// setters ignore a key their model lacks while still answering "saved", so
// neither mistake would ever surface.
type EntityModel struct {
	fields map[string]ModelField
}

// ModelField is one field of an EntityModel.
type ModelField struct {
	Name string
	// Default is the field's default in OPNsense's string form. For a list
	// field it is the keys the template marks selected, comma-joined.
	Default string
	// List marks a field whose value is one or more keys of Options.
	List bool
	// Options maps each option key the device offers to its label. A list
	// field with nothing to offer yet (no categories defined, say) has none.
	Options map[string]string
	// Nested marks a container: a flat setter body cannot set it.
	Nested bool
}

// ParseEntityModel reads a template: the object under the entity's wrapper
// key. A string is a plain field and its value the default; an object whose
// members are {value, selected} pairs is a list field; an array is a list field
// whose options are its members (OPNsense sends an empty option list as []).
// Any other object is a container.
func ParseEntityModel(template map[string]interface{}) EntityModel {
	model := EntityModel{fields: make(map[string]ModelField, len(template))}
	for name, raw := range template {
		field := ModelField{Name: name}
		switch v := raw.(type) {
		case nil:
		case string:
			field.Default = v
		case bool:
			field.Default = BoolToOPNsense(v)
		case float64:
			field.Default = strconv.FormatFloat(v, 'f', -1, 64)
		case []interface{}:
			field.List = true
			field.Options = make(map[string]string, len(v))
			for _, item := range v {
				if key, ok := item.(string); ok {
					field.Options[key] = key
				}
			}
		case map[string]interface{}:
			options, selected, ok := parseOptionList(v)
			if !ok {
				field.Nested = true
				break
			}
			field.List = true
			field.Options = options
			field.Default = strings.Join(selected, ",")
		default:
			field.Nested = true
		}
		model.fields[name] = field
	}
	return model
}

// parseOptionList reads OPNsense's option-list shape, {key: {"value": label,
// "selected": 0|1}}. ok is false when any member is not such a pair.
func parseOptionList(raw map[string]interface{}) (options map[string]string, selected []string, ok bool) {
	options = make(map[string]string, len(raw))
	for key, member := range raw {
		pair, isMap := member.(map[string]interface{})
		if !isMap {
			return nil, nil, false
		}
		label, hasLabel := pair["value"]
		if !hasLabel {
			return nil, nil, false
		}
		if s, isString := label.(string); isString {
			options[key] = s
		} else {
			options[key] = fmt.Sprint(label)
		}
		if isSelected(pair["selected"]) {
			selected = append(selected, key)
		}
	}
	sort.Strings(selected)
	return options, selected, true
}

func isSelected(v interface{}) bool {
	switch s := v.(type) {
	case bool:
		return s
	case float64:
		return s != 0
	case string:
		return s == "1"
	}
	return false
}

// Field returns the named field.
func (m EntityModel) Field(name string) (ModelField, bool) {
	f, ok := m.fields[name]
	return f, ok
}

// Names returns every field name, sorted.
func (m EntityModel) Names() []string {
	names := make([]string, 0, len(m.fields))
	for name := range m.fields {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Len is the number of fields.
func (m EntityModel) Len() int {
	return len(m.fields)
}

// OptionKeys returns the field's option keys, sorted.
func (f ModelField) OptionKeys() []string {
	keys := make([]string, 0, len(f.Options))
	for key := range f.Options {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// Values returns the value of every field but the containers. Read from an
// entity's get<Entity>/<uuid> answer, which has its template's shape, these
// are the entity's values: a list field's selected keys, comma-joined.
func (m EntityModel) Values() map[string]string {
	values := make(map[string]string, len(m.fields))
	for name, field := range m.fields {
		if !field.Nested {
			values[name] = field.Default
		}
	}
	return values
}

// IsBoolean reports whether the field holds OPNsense's boolean form: a plain
// field whose default is "0" or "1".
func (f ModelField) IsBoolean() bool {
	return !f.List && !f.Nested && (f.Default == "0" || f.Default == "1")
}
