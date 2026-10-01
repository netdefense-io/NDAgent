package pathfinder

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

func inputNames(names ...string) map[string]bool {
	m := map[string]bool{}
	for _, n := range names {
		m[n] = true
	}
	return m
}

func TestScrubHTMLInputs(t *testing.T) {
	tests := []struct {
		name    string
		names   map[string]bool
		in      string
		want    string
		changed int
	}{
		{
			name:    "the DHCPv6 key secret of interfaces.php",
			names:   inputNames("adv_dhcp6_key_info_statement_secret"),
			in:      `<i><?=gettext("secret"); ?></i><input name="adv_dhcp6_key_info_statement_secret" type="text" id="adv_dhcp6_key_info_statement_secret" value="s3cr3t&amp;&quot;x" />` + "\n",
			want:    `<i><?=gettext("secret"); ?></i><input name="adv_dhcp6_key_info_statement_secret" type="text" id="adv_dhcp6_key_info_statement_secret" value="" />` + "\n",
			changed: 1,
		},
		{
			name:    "the PPP password",
			names:   inputNames("password"),
			in:      `<input name="username" type="text" id="username" value="isp-user" /><input name="password" type="password" autocomplete="new-password" id="password" value="hunter2" />`,
			want:    `<input name="username" type="text" id="username" value="isp-user" /><input name="password" type="password" autocomplete="new-password" id="password" value="" />`,
			changed: 1,
		},
		{
			name:    "a name that only starts like a secret's is not one",
			names:   inputNames("ddnsdomainkey"),
			in:      `<input name="ddnsdomainkeyname" type="text" value="key-name" /><input name="ddnsdomainkey" type="text" value="YWJj" />`,
			want:    `<input name="ddnsdomainkeyname" type="text" value="key-name" /><input name="ddnsdomainkey" type="text" value="" />`,
			changed: 1,
		},
		{
			name:    "the value before the name",
			names:   inputNames("omapikey"),
			in:      `<input value="k3y" type="text" name="omapikey"><br />`,
			want:    `<input value="" type="text" name="omapikey"><br />`,
			changed: 1,
		},
		{
			name:    "single quotes, bare values, upper case, spaces and line breaks",
			names:   inputNames("password"),
			in:      "<INPUT NAME='password' TYPE=text VALUE='a b'>\n<input\n  name = \"password\"\n  value = bare\n>\n<input name=password value=bare2/>",
			want:    "<INPUT NAME='password' TYPE=text VALUE=''>\n<input\n  name = \"password\"\n  value = \"\"\n>\n<input name=password value=\"\">",
			changed: 3,
		},
		{
			name:    "an attribute that follows a quoted value with no space",
			names:   inputNames("password"),
			in:      `<input value="x"name="password" id="p">`,
			want:    `<input value=""name="password" id="p">`,
			changed: 1,
		},
		{
			name:    "a duplicated value attribute is blanked everywhere",
			names:   inputNames("password"),
			in:      `<input name="password" value="one" value="two">`,
			want:    `<input name="password" value="" value="">`,
			changed: 2,
		},
		{
			name:    "a duplicated name attribute",
			names:   inputNames("password"),
			in:      `<input name="visible" name="password" value="x">`,
			want:    `<input name="visible" name="password" value="">`,
			changed: 1,
		},
		{
			name:    "a greater-than sign inside the quotes does not end the tag",
			names:   inputNames("password"),
			in:      `<input name="password" value="a>b" /><p>after</p>`,
			want:    `<input name="password" value="" /><p>after</p>`,
			changed: 1,
		},
		{
			name:  "a tag is read the way a browser reads it: this name ends at the second quote",
			names: inputNames("password"),
			in:    `<input name="password value="x">`,
			want:  `<input name="password value="x">`,
		},
		{
			name:  "a field that is blank already",
			names: inputNames("password"),
			in:    `<input name="password" value="" /><input name="password" />`,
			want:  `<input name="password" value="" /><input name="password" />`,
		},
		{
			name:  "the same name on an element that is not an input",
			names: inputNames("password"),
			in:    `<select name="password" value="x"></select><div name="password" value="y"></div><inputx name="password" value="z">`,
			want:  `<select name="password" value="x"></select><div name="password" value="y"></div><inputx name="password" value="z">`,
		},
		{
			name:  "a name that differs in case is another field",
			names: inputNames("password"),
			in:    `<input name="Password" value="x">`,
			want:  `<input name="Password" value="x">`,
		},
		{
			name:    "an element inside a script or a comment is blanked too",
			names:   inputNames("password"),
			in:      `<!-- <input name="password" value="a"> --><script>var t='<input name="password" value="b">';</script>`,
			want:    `<!-- <input name="password" value=""> --><script>var t='<input name="password" value="">';</script>`,
			changed: 2,
		},
		{
			name:  "a page without a named input comes back as it was",
			names: inputNames("password"),
			in:    "<html><body><input name=\"user\" value=\"x\"><textarea name=\"password\">x</textarea>\r\n<p>a < b</p></body></html>",
			want:  "<html><body><input name=\"user\" value=\"x\"><textarea name=\"password\">x</textarea>\r\n<p>a < b</p></body></html>",
		},
		{
			name:    "bytes that are not text are copied",
			names:   inputNames("password"),
			in:      "\xff\xfe<input name=\"password\" value=\"\x00\xff\">\x00",
			want:    "\xff\xfe<input name=\"password\" value=\"\">\x00",
			changed: 1,
		},
		{
			name:    "several names of one page",
			names:   inputNames("key1", "key2", "passphrase"),
			in:      `<input name="key1" value="a"><input name="key2" value="b"><input name="key3" value="c"><input name="passphrase" value="d">`,
			want:    `<input name="key1" value=""><input name="key2" value=""><input name="key3" value="c"><input name="passphrase" value="">`,
			changed: 3,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, changed, err := scrubHTMLInputs([]byte(tt.in), tt.names)
			if err != nil {
				t.Fatalf("scrubHTMLInputs: %v", err)
			}
			if string(got) != tt.want {
				t.Errorf("got  %q\nwant %q", got, tt.want)
			}
			if changed != tt.changed {
				t.Errorf("changed = %d, want %d", changed, tt.changed)
			}
		})
	}
}

// An input tag that is not closed, or whose quote is not, cannot be read the way
// a browser reads it: the page is refused, not passed along.
func TestScrubHTMLInputs_MalformedTagsAreErrors(t *testing.T) {
	pages := map[string]string{
		"a named tag that never ends":        `<input name="password" value="x"`,
		"an unnamed tag that never ends":     `<p>x</p><input type="text" value="x"`,
		"an unterminated quote":              `<input name="password" value="x>` + strings.Repeat("a", 100),
		"the tag name alone at the very end": `<p>x</p><input`,
		"white space at the very end":        `<input `,
		"an equals sign at the very end":     `<input name=`,
		"a tag longer than any real one":     `<input name="password" value="` + strings.Repeat("a", maxInputTagBytes) + `">`,
	}
	for name, page := range pages {
		t.Run(name, func(t *testing.T) {
			if got, _, err := scrubHTMLInputs([]byte(page), inputNames("password")); err == nil {
				t.Errorf("got %q, want an error", got)
			}
		})
	}
}

// Every byte outside the named fields' values arrives as it was, and no planted
// secret survives, on pages assembled from every spelling above.
func TestScrubHTMLInputs_RandomPages(t *testing.T) {
	names := inputNames("password", "ddnsdomainkey")
	r := rand.New(rand.NewSource(7))
	quotes := []string{`"`, `'`, ""}
	filler := []string{
		"<p>text</p>", "\n", "  ", `<input name="user" value="visible">`, `<input name="passwordx" value="kept">`,
		`<select name="password"><option value="x">x</option></select>`, "<!-- c -->", "a < b", `<br />`, `<inputx name="password" value="kept">`,
	}
	secretsLeft := 0
	for i := 0; i < 3000; i++ {
		var in, want strings.Builder
		for n := r.Intn(8); n >= 0; n-- {
			if r.Intn(2) == 0 {
				f := filler[r.Intn(len(filler))]
				in.WriteString(f)
				want.WriteString(f)
				continue
			}
			secret := fmt.Sprintf("S%dE%d", i, n)
			q := quotes[r.Intn(len(quotes))]
			name := []string{"password", "ddnsdomainkey"}[r.Intn(2)]
			tag := "input"
			if r.Intn(3) == 0 {
				tag = "INPUT"
			}
			nameAttr := fmt.Sprintf(`name="%s"`, name)
			if q == "" {
				nameAttr = fmt.Sprintf(`name=%s`, name)
			}
			extra := []string{"", ` type="text"`, " id='x'", "\n  class=\"form-control\"", " disabled"}[r.Intn(5)]
			valueFirst := r.Intn(2) == 0
			value := fmt.Sprintf(`value=%s%s%s`, q, secret, q)
			blank := fmt.Sprintf(`value=%s%s`, q, q)
			if q == "" {
				blank = `value=""`
			}
			end := []string{">", " />", "/>"}[r.Intn(3)]
			if q == "" && end == "/>" {
				end = " />" // a bare value would swallow the slash
			}
			if valueFirst {
				fmt.Fprintf(&in, "<%s %s%s %s%s", tag, value, extra, nameAttr, end)
				fmt.Fprintf(&want, "<%s %s%s %s%s", tag, blank, extra, nameAttr, end)
			} else {
				fmt.Fprintf(&in, "<%s %s%s %s%s", tag, nameAttr, extra, value, end)
				fmt.Fprintf(&want, "<%s %s%s %s%s", tag, nameAttr, extra, blank, end)
			}
			secretsLeft++
		}
		got, _, err := scrubHTMLInputs([]byte(in.String()), names)
		if err != nil {
			t.Fatalf("page %d: %v\n%s", i, err, in.String())
		}
		if string(got) != want.String() {
			t.Fatalf("page %d\n in:   %q\n got:  %q\n want: %q", i, in.String(), got, want.String())
		}
	}
	if secretsLeft < 3000 {
		t.Fatalf("the generator planted only %d secrets", secretsLeft)
	}
}

func FuzzScrubHTMLInputs(f *testing.F) {
	names := inputNames("password")
	for _, seed := range []string{
		`<input name="password" value="x">`, `<input value='a'name=password>`, `<INPUT NAME = "password" VALUE=b/>`, `<input`, `<input name="password"`,
		`<p><input name=password value="a>b"></p>`, `<input name="password" value="x" value="y">`, "",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, page []byte) {
		out, changed, err := scrubHTMLInputs(page, names)
		if err != nil {
			return
		}
		if changed == 0 && string(out) != string(page) {
			t.Fatalf("nothing changed, yet %q became %q", page, out)
		}
		// a second pass finds nothing left to blank
		again, changedAgain, err := scrubHTMLInputs(out, names)
		if err != nil || changedAgain != 0 || string(again) != string(out) {
			t.Fatalf("not idempotent: %q -> %q -> %q (%d, %v)", page, out, again, changedAgain, err)
		}
	})
}
