package pathfinder

import (
	"bytes"
	"encoding/json"
	"math/rand"
	"reflect"
	"strings"
	"testing"
)

func secretKeys(keys ...jsonKey) jsonSecrets {
	m := map[string]jsonKey{}
	for _, k := range keys {
		m[k.name] = k
	}
	return jsonSecrets{keys: m}
}

func keyNamed(names ...string) jsonSecrets {
	var keys []jsonKey
	for _, n := range names {
		keys = append(keys, jsonKey{name: n})
	}
	return secretKeys(keys...)
}

func TestScrubJSON_BlanksNamedKeysAndNothingElse(t *testing.T) {
	tests := []struct {
		name    string
		secrets jsonSecrets
		in      string
		want    string
		changed int
	}{
		{
			name:    "a get response",
			secrets: keyNamed("password", "otp_seed"),
			in:      `{"user":{"name":"alice","password":"","otp_seed":"JBSWY3DPEHPK3PXP","descr":"x"}}`,
			want:    `{"user":{"name":"alice","password":"","otp_seed":"","descr":"x"}}`,
			changed: 1,
		},
		{
			name:    "every row of a grid",
			secrets: keyNamed("password"),
			in:      `{"rows":[{"uuid":"a","password":"$2y$11$abc"},{"uuid":"b","password":"$2y$11$def"}],"rowCount":2,"total":2,"current":1}`,
			want:    `{"rows":[{"uuid":"a","password":""},{"uuid":"b","password":""}],"rowCount":2,"total":2,"current":1}`,
			changed: 2,
		},
		{
			name:    "white space, key order, number spelling and escapes outside the secret are kept",
			secrets: keyNamed("psk"),
			in:      "{\n  \"z\": 1.50e+2,\n  \"psk\" :   \"s3cr3t\",\n  \"a\": \"caf\\u00e9 \\/ \\\"q\\\"\",\n  \"n\": [1, 2 ,3]\n}\n",
			want:    "{\n  \"z\": 1.50e+2,\n  \"psk\" :   \"\",\n  \"a\": \"caf\\u00e9 \\/ \\\"q\\\"\",\n  \"n\": [1, 2 ,3]\n}\n",
			changed: 1,
		},
		{
			name:    "a key spelled with escapes is the same key",
			secrets: keyNamed("password"),
			in:      `{"password":"x","password":"y"}`,
			want:    `{"password":"","password":""}`,
			changed: 2,
		},
		{
			name:    "a duplicate key is blanked both times",
			secrets: keyNamed("password"),
			in:      `{"password":"a","x":1,"password":"b"}`,
			want:    `{"password":"","x":1,"password":""}`,
			changed: 2,
		},
		{
			name:    "a number is blanked to zero",
			secrets: keyNamed("pin"),
			in:      `{"pin":123456,"other":123456}`,
			want:    `{"pin":0,"other":123456}`,
			changed: 1,
		},
		{
			name:    "a null and a bool hold no secret",
			secrets: keyNamed("password"),
			in:      `{"a":{"password":null},"b":{"password":false},"c":{"password":true}}`,
			want:    `{"a":{"password":null},"b":{"password":false},"c":{"password":true}}`,
		},
		{
			name:    "an entry of an option list that is called like a secret is not the secret",
			secrets: keyNamed("password"),
			in:      `{"alias":{"content":{"password":{"selected":0,"value":"password"},"web":{"selected":1,"value":"web"}}}}`,
			want:    `{"alias":{"content":{"password":{"selected":0,"value":"password"},"web":{"selected":1,"value":"web"}}}}`,
		},
		{
			name:    "a secret nested inside an object of the same name is still found",
			secrets: keyNamed("password"),
			in:      `{"password":{"password":"x","other":"y"}}`,
			want:    `{"password":{"password":"","other":"y"}}`,
			changed: 1,
		},
		{
			name:    "an array under a scalar key is searched, not blanked",
			secrets: keyNamed("key"),
			in:      `{"key":["a",{"key":"b"}]}`,
			want:    `{"key":["a",{"key":""}]}`,
			changed: 1,
		},
		{
			name:    "a key that holds a list is blanked to an empty list",
			secrets: secretKeys(jsonKey{name: "m_enc", kinds: kindString | kindArray}, jsonKey{name: "m_auth", kinds: kindString | kindArray}),
			in:      `{"records":[{"alg_enc":"rijndael-cbc","m_enc":["0x0011","2233"],"m_auth":["aabb"],"spi":"2"},{"m_enc":"00","m_auth":[]}]}`,
			want:    `{"records":[{"alg_enc":"rijndael-cbc","m_enc":[],"m_auth":[],"spi":"2"},{"m_enc":"","m_auth":[]}]}`,
			changed: 3,
		},
		{
			name:    "a key that holds an object is blanked to an empty object",
			secrets: secretKeys(jsonKey{name: "httpdAllow", kinds: kindString | kindObject}),
			in:      `{"monit":{"general":{"httpdAllow":{"admin:secret":{"value":"admin:secret","selected":1}},"port":{"2812":{"selected":1}}}}}`,
			want:    `{"monit":{"general":{"httpdAllow":{},"port":{"2812":{"selected":1}}}}}`,
			changed: 1,
		},
		{
			name:    "a string is one JSON value whatever it contains",
			secrets: keyNamed("password"),
			in:      `{"password":"a\"}, \"password\": \"b","x":"password"}`,
			want:    `{"password":"","x":"password"}`,
			changed: 1,
		},
		{
			name:    "the root may be an array",
			secrets: keyNamed("password"),
			in:      `[{"password":"a"},{"password":"b"},3,"password"]`,
			want:    `[{"password":""},{"password":""},3,"password"]`,
			changed: 2,
		},
		{
			name:    "an already blank secret is not counted",
			secrets: keyNamed("password"),
			in:      `{"password":""}`,
			want:    `{"password":""}`,
		},
		{
			name:    "nothing to scrub",
			secrets: keyNamed("password"),
			in:      `{"a":[1,2,{"b":null}]}`,
			want:    `{"a":[1,2,{"b":null}]}`,
		},
		{
			name:    "scalars at the root",
			secrets: keyNamed("password"),
			in:      `"password"`,
			want:    `"password"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, changed, err := scrubJSON([]byte(tt.in), tt.secrets)
			if err != nil {
				t.Fatalf("scrubJSON: %v", err)
			}
			if string(got) != tt.want {
				t.Errorf("scrubJSON(%s)\n got  %s\n want %s", tt.in, got, tt.want)
			}
			if changed != tt.changed {
				t.Errorf("changed = %d, want %d", changed, tt.changed)
			}
		})
	}
}

func TestScrubJSON_Paths(t *testing.T) {
	secrets := jsonSecrets{paths: []jsonPath{
		{segments: []string{"ids", "fileTags", "tag", "*", "value"}},
		{segments: []string{"properties", "*"}},
	}}
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "the value of a tag is blanked where the path says, and its property is not",
			in:   `{"ids":{"fileTags":{"tag":{"0a":{"property":"oinkcode","value":"abc123"},"0b":{"property":"x","value":"y"}}},"general":{"mode":{"ips":{"value":"IPS","selected":1}}}}}`,
			want: `{"ids":{"fileTags":{"tag":{"0a":{"property":"oinkcode","value":""},"0b":{"property":"x","value":""}}},"general":{"mode":{"ips":{"value":"IPS","selected":1}}}}}`,
		},
		{
			name: "the same name anywhere else is left alone",
			in:   `{"ids":{"general":{"value":"kept"},"fileTags":{"value":"kept","tag":{"value":"kept"}}},"value":"kept"}`,
			want: `{"ids":{"general":{"value":"kept"},"fileTags":{"value":"kept","tag":{"value":"kept"}}},"value":"kept"}`,
		},
		{
			name: "every value of the properties is blanked and their names are kept",
			in:   `{"properties":{"oinkcode":"abc","token":"def"}}`,
			want: `{"properties":{"oinkcode":"","token":""}}`,
		},
		{
			name: "properties that arrive as a list",
			in:   `{"properties":["abc","def"]}`,
			want: `{"properties":["",""]}`,
		},
		{
			name: "an empty list of properties",
			in:   `{"properties":[]}`,
			want: `{"properties":[]}`,
		},
		{
			name: "properties deeper down are not these",
			in:   `{"x":{"properties":{"oinkcode":"abc"}}}`,
			want: `{"x":{"properties":{"oinkcode":"abc"}}}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _, err := scrubJSON([]byte(tt.in), secrets)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tt.want {
				t.Errorf("got  %s\nwant %s", got, tt.want)
			}
		})
	}
}

func TestScrubJSON_URLUserinfo(t *testing.T) {
	secrets := secretKeys(jsonKey{name: "mmonitUrl", userinfo: true})
	tests := []struct {
		url  string
		want string
	}{
		{"http://monit:monit@192.168.1.10:8080/collector", "http://192.168.1.10:8080/collector"},
		{"https://user@host.example/collector", "https://host.example/collector"},
		{"https://user:p@ss:w@rd@host.example:8443/c", "https://host.example:8443/c"},
		{"https://monit:pa%2Fss@mmonit.example.invalid:8443/collector", "https://mmonit.example.invalid:8443/collector"},
		{"https://monit:pa%3Fss%23@mmonit.example.invalid/collector", "https://mmonit.example.invalid/collector"},
		{"https://monit:p@ss@mmonit.example.invalid/a@b", "https://mmonit.example.invalid/a@b"},
		{"http://host.example:8080/collector", "http://host.example:8080/collector"},
		// an @ after the authority may still be the end of a userinfo whose password holds
		// a /, a ? or a # that was never escaped (the value is rendered into monitrc
		// as it is stored): it is not told from a literal @ in a path, and the URL is lost
		{"https://monit:pa/ss@mmonit.example.invalid:8443/collector", ""},
		{"https://monit:pa?ss@mmonit.example.invalid:8443/collector", ""},
		{"https://monit:pa#ss@mmonit.example.invalid:8443/collector", ""},
		{"https://monit:12345/ab@mmonit.example.invalid/collector", ""},
		{"https://monit:pa/ss/@mmonit.example.invalid/collector", ""},
		{"http://host.example/a@b", ""},
		{"http://host.example?x=a@b", ""},
		{"http://host.example:8080#frag@x", ""},
		{"http://[::1]:8080/c", "http://[::1]:8080/c"},
		{"", ""},
		// not a URL with an authority, but carries an @: better to lose it
		{"monit:monit@host/collector", ""},
		{"host", "host"},
	}
	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			in, _ := json.Marshal(map[string]string{"mmonitUrl": tt.url})
			got, _, err := scrubJSON(in, secrets)
			if err != nil {
				t.Fatal(err)
			}
			var out map[string]string
			if err := json.Unmarshal(got, &out); err != nil {
				t.Fatalf("output is not JSON: %s", got)
			}
			if out["mmonitUrl"] != tt.want {
				t.Errorf("mmonitUrl = %q, want %q", out["mmonitUrl"], tt.want)
			}
			if tt.want == tt.url && !bytes.Equal(got, in) {
				t.Errorf("an unchanged URL must leave the bytes alone: %s -> %s", in, got)
			}
		})
	}

	// the spelling of a URL that needs no edit survives, escapes and all
	raw := `{"mmonitUrl":"http:\/\/host.example\/cA"}`
	got, changed, err := scrubJSON([]byte(raw), secrets)
	if err != nil || string(got) != raw || changed != 0 {
		t.Errorf("got %s, %d, %v; want the input back untouched", got, changed, err)
	}
}

// Anything that is not exactly one JSON value is refused, never passed along.
func TestScrubJSON_MalformedBodiesAreErrors(t *testing.T) {
	bodies := map[string]string{
		"empty":               ``,
		"white space":         "  \n",
		"truncated object":    `{"password":"x"`,
		"truncated string":    `{"password":"x`,
		"truncated array":     `[{"password":"x"},`,
		"trailing comma":      `{"password":"x",}`,
		"missing colon":       `{"password" "x"}`,
		"single quotes":       `{'password':'x'}`,
		"unquoted key":        `{password:"x"}`,
		"trailing value":      `{"password":"x"} {"a":1}`,
		"trailing text":       `{"password":"x"}x`,
		"html":                `<html><body>login</body></html>`,
		"a csv":               "a;b\n1;2\n",
		"NaN":                 `{"a":NaN}`,
		"byte order mark":     "\xef\xbb\xbf{\"password\":\"x\"}",
		"a control character": "{\"a\":\"\x01\"}",
		"leading zero":        `{"a":01}`,
		"a lone surrogate is fine but a bare backslash is not": `{"a":"\x"}`,
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			if got, _, err := scrubJSON([]byte(body), keyNamed("password")); err == nil {
				t.Errorf("scrubJSON(%q) = %q, want an error", body, got)
			}
		})
	}
}

// A document nested about as deep as encoding/json accepts is still read.
func TestScrubJSON_DeepNesting(t *testing.T) {
	const depth = 5000
	in := strings.Repeat(`{"a":`, depth) + `{"password":"x"}` + strings.Repeat(`}`, depth)
	got, changed, err := scrubJSON([]byte(in), keyNamed("password"))
	if err != nil || changed != 1 {
		t.Fatalf("got %d changes, %v", changed, err)
	}
	if strings.Contains(string(got), `"x"`) {
		t.Error("the secret survived")
	}
}

// reference is an independent implementation of the rules over decoded values,
// to hold scrubJSON to: the two must agree on every document.
func reference(v interface{}, secrets jsonSecrets, path []string, asKey *string) interface{} {
	blank := func(kinds valueKinds) (interface{}, bool) {
		if kinds == 0 {
			kinds = kindsScalar
		}
		switch x := v.(type) {
		case string:
			if kinds&kindString != 0 {
				return "", true
			}
		case json.Number:
			if kinds&kindNumber != 0 {
				return json.Number("0"), true
			}
		case []interface{}:
			if kinds&kindArray != 0 {
				return []interface{}{}, true
			}
		case map[string]interface{}:
			if kinds&kindObject != 0 {
				return map[string]interface{}{}, true
			}
		default:
			_ = x
		}
		return nil, false
	}
	if asKey != nil {
		if k, ok := secrets.keys[*asKey]; ok {
			if out, done := blank(k.kinds); done {
				return out
			}
		}
	}
	for _, p := range secrets.paths {
		if p.matches(path) {
			if out, done := blank(p.kinds); done {
				return out
			}
		}
	}
	switch x := v.(type) {
	case map[string]interface{}:
		out := make(map[string]interface{}, len(x))
		for k, child := range x {
			k := k
			out[k] = reference(child, secrets, append(append([]string{}, path...), k), &k)
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(x))
		for i, child := range x {
			out[i] = reference(child, secrets, append(append([]string{}, path...), itoa(i)), nil)
		}
		return out
	}
	return v
}

func itoa(i int) string {
	b, _ := json.Marshal(i)
	return string(b)
}

func decodeExact(t testing.TB, b []byte) interface{} {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v interface{}
	if err := dec.Decode(&v); err != nil {
		t.Fatalf("decode %q: %v", b, err)
	}
	return v
}

// randomDoc builds a document out of the names the rules use, so that secrets
// and look-alikes turn up at every depth and in every type.
func randomDoc(r *rand.Rand, depth int) interface{} {
	names := []string{"password", "key", "m_enc", "httpdAllow", "value", "tag", "properties", "ids", "fileTags", "a", "selected", "0", "1"}
	if depth <= 0 {
		switch r.Intn(6) {
		case 0:
			return "s" + itoa(r.Intn(100))
		case 1:
			return json.Number(itoa(r.Intn(1000)))
		case 2:
			return json.Number("1.5e3")
		case 3:
			return nil
		case 4:
			return r.Intn(2) == 0
		default:
			return ""
		}
	}
	switch r.Intn(3) {
	case 0:
		m := map[string]interface{}{}
		for i := r.Intn(5); i > 0; i-- {
			m[names[r.Intn(len(names))]] = randomDoc(r, depth-1)
		}
		return m
	case 1:
		var a []interface{}
		for i := r.Intn(4); i > 0; i-- {
			a = append(a, randomDoc(r, depth-1))
		}
		if a == nil {
			a = []interface{}{}
		}
		return a
	default:
		return randomDoc(r, 0)
	}
}

func TestScrubJSON_AgreesWithTheReferenceOnRandomDocuments(t *testing.T) {
	secrets := jsonSecrets{
		keys: map[string]jsonKey{
			"password":   {name: "password"},
			"key":        {name: "key"},
			"m_enc":      {name: "m_enc", kinds: kindString | kindArray},
			"httpdAllow": {name: "httpdAllow", kinds: kindString | kindObject},
		},
		paths: []jsonPath{
			{segments: []string{"ids", "fileTags", "tag", "*", "value"}},
			{segments: []string{"properties", "*"}, kinds: kindString | kindNumber | kindObject | kindArray},
		},
	}
	r := rand.New(rand.NewSource(1))
	blankedSomething := 0
	for i := 0; i < 4000; i++ {
		doc := randomDoc(r, 1+r.Intn(6))
		var in []byte
		var err error
		if i%2 == 0 {
			in, err = json.Marshal(doc)
		} else {
			in, err = json.MarshalIndent(doc, "", "  ")
		}
		if err != nil {
			t.Fatal(err)
		}
		got, changed, err := scrubJSON(in, secrets)
		if err != nil {
			t.Fatalf("document %d: %v\n%s", i, err, in)
		}
		want := reference(decodeExact(t, in), secrets, nil, nil)
		if !reflect.DeepEqual(decodeExact(t, got), want) {
			t.Fatalf("document %d differs from the reference\nin:  %s\ngot: %s", i, in, got)
		}
		if changed == 0 {
			if !bytes.Equal(got, in) {
				t.Fatalf("document %d: nothing blanked, but the bytes changed\nin:  %s\ngot: %s", i, in, got)
			}
		} else {
			blankedSomething++
		}
	}
	if blankedSomething < 500 {
		t.Fatalf("only %d of the random documents held a secret; the generator no longer exercises the rules", blankedSomething)
	}
}

func FuzzScrubJSON(f *testing.F) {
	secrets := jsonSecrets{
		keys: map[string]jsonKey{
			"password": {name: "password"},
			"m_enc":    {name: "m_enc", kinds: kindString | kindArray},
		},
		paths: []jsonPath{{segments: []string{"properties", "*"}}},
	}
	for _, seed := range []string{
		`{"password":"x"}`, `[{"password":1},{"m_enc":[1,2]}]`, `{"properties":{"a":"b"}}`, `{"a":{"b":[]}}`,
		`{"password":{"password":"x"}}`, "  {\"password\" : \"x\"}  ", `{"password":"x"}`, `[`, ``, `{"a":"\ud800"}`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		got, _, err := scrubJSON(in, secrets)
		if !json.Valid(in) {
			if err == nil {
				t.Fatalf("invalid input %q accepted as %q", in, got)
			}
			return
		}
		if err != nil {
			t.Fatalf("valid input %q refused: %v", in, err)
		}
		if !json.Valid(got) {
			t.Fatalf("output %q is not JSON (input %q)", got, in)
		}
		want := reference(decodeExact(t, in), secrets, nil, nil)
		if !reflect.DeepEqual(decodeExact(t, got), want) {
			t.Fatalf("output %q differs from the reference for %q", got, in)
		}
	})
}
