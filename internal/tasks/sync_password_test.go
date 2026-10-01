package tasks

import (
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/netdefense-io/ndagent/internal/opnapi"
)

// The contract of a USER snippet's password: it is plaintext. OPNsense hashes
// whatever it is sent, so a hash in a snippet would become the password itself.

const passwordIsHashCode = "USER_PASSWORD_IS_HASH"

// hashOf builds a value of each hash family's shape out of filler.
func hashOf(t *testing.T, family string) string {
	t.Helper()
	var v string
	switch family {
	case "bcrypt $2y$":
		v = "$2y$11$./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxy"
	case "bcrypt $2a$ cost 04":
		v = "$2a$04$DEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123"
	case "sha512":
		v = "$6$saltsalt$" + strings.Repeat("A", 86)
	case "sha512 with rounds":
		v = "$6$rounds=5000$saltsalt$" + strings.Repeat("B", 86)
	case "sha256":
		v = "$5$saltsalt$" + strings.Repeat("C", 43)
	case "md5":
		v = "$1$salt$" + strings.Repeat("D", 22)
	case "argon2id":
		v = "$argon2id$v=19$m=65536,t=4,p=1$" + strings.Repeat("E", 22) + "$" + strings.Repeat("F", 43)
	case "argon2i":
		v = "$argon2i$v=19$m=65536,t=4,p=1$" + strings.Repeat("G", 22) + "$" + strings.Repeat("H", 43)
	default:
		t.Fatalf("unknown family %q", family)
	}
	if !opnapi.IsCryptHashShaped(v) {
		t.Fatalf("the %s fixture is not hash-shaped", family)
	}
	return v
}

var hashFamilies = []string{"bcrypt $2y$", "bcrypt $2a$ cost 04", "sha512", "sha512 with rounds", "sha256", "md5", "argon2id", "argon2i"}

func bcryptOf(t *testing.T, plaintext string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(plaintext), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	return string(h)
}

func TestUserPasswordIsHash_RefusedForEveryShape(t *testing.T) {
	for _, family := range hashFamilies {
		t.Run(family, func(t *testing.T) {
			users, groups := liveAccounts()
			f := newFakeAccounts(t, users, groups)
			hash := hashOf(t, family)

			result := runGate(t, f, []opnapi.APIUserPayload{
				{Name: "svc", Password: hash, SnippetName: "svc-snippet", SnippetIndex: 3},
				{Name: "sibling", Password: "a-plain-password"},
			}, nil, false)

			items := refusedItems(result)
			if len(items) != 1 || items[0].Name != "svc" || items[0].Type != "user" {
				t.Fatalf("refused items = %+v, want exactly svc", items)
			}
			if items[0].Code != passwordIsHashCode || items[0].Status != "blocked" {
				t.Errorf("item = %+v, want code %s, blocked", items[0], passwordIsHashCode)
			}
			if strings.Contains(items[0].Error, hash) {
				t.Error("the message echoes the value")
			}
			if result.Success {
				t.Error("a refusal fails the task")
			}
			assertErrorHasMatchingResultItem(t, "password is a hash", result.Errors, result.Results)
			if f.wroteAnythingFor("user", "svc") {
				t.Errorf("a refused element must not reach OPNsense: %v", f.writes)
			}
			if !f.wrote("add", "user", "sibling") {
				t.Errorf("the sibling must still apply: %v", f.writes)
			}
		})
	}
}

func TestUserPasswordIsHash_PinsTheMessage(t *testing.T) {
	users, groups := liveAccounts()
	f := newFakeAccounts(t, users, groups)

	result := runGate(t, f, []opnapi.APIUserPayload{{Name: "svc", Password: hashOf(t, "bcrypt $2y$"), SnippetName: "svc-snippet", SnippetIndex: 3}}, nil, false)

	want := `rejected: user snippet "svc-snippet" (index 3) for user "svc" carries a password with the shape of a password hash. ` +
		`OPNsense hashes whatever it is sent, so a hash would become the password itself and lock the intended one out; ` +
		`put the plaintext password in a secret variable (${NAME}) and sync again`
	if len(result.Errors) != 1 || result.Errors[0] != want {
		t.Errorf("errors = %q\nwant    %q", result.Errors, want)
	}
}

func TestUserPasswordIsHash_NeverDeletesWhatIsThere(t *testing.T) {
	users, groups := liveAccounts()
	users = append(users, row{"uuid": "uu-managed", "uid": "2060", "name": "svc-managed", "scope": "user", "priv": "", "group_memberships": "", "is_admin": "0", "descr": "[nd-template:ops]", "password": hashOf(t, "sha512")})
	f := newFakeAccounts(t, users, groups)

	result := runGate(t, f, []opnapi.APIUserPayload{{Name: "svc-managed", Password: hashOf(t, "bcrypt $2y$"), Templates: []string{"ops"}}}, nil, false)

	if len(refusedItems(result)) != 1 {
		t.Fatalf("items = %+v, want one refusal", result.Results)
	}
	if f.wrote("del", "user", "svc-managed") || f.wroteAnythingFor("user", "svc-managed") {
		t.Errorf("an existing managed user whose element was refused was touched: %v", f.writes)
	}
}

// TestUserPasswordIsHash_ByteIdenticalToTheStoredHashIsANoOp: a snippet pulled
// from this very device and synced back carries the hash the device holds. That
// changes nothing, so the password is left out and the rest of the element applies.
func TestUserPasswordIsHash_ByteIdenticalToTheStoredHashIsANoOp(t *testing.T) {
	stored := hashOf(t, "bcrypt $2y$")

	t.Run("the same user", func(t *testing.T) {
		users, groups := liveAccounts()
		users[8]["password"] = stored // nd-hm-plain
		f := newFakeAccounts(t, users, groups)

		result := runGate(t, f, []opnapi.APIUserPayload{{Name: "nd-hm-plain", Password: stored, Descr: "a new description"}}, nil, false)

		if len(refusedItems(result)) != 0 || !result.Success {
			t.Fatalf("a no-op must not be refused: %+v", result)
		}
		bodies := f.bodies["set user nd-hm-plain"]
		if len(bodies) != 1 {
			t.Fatalf("set calls = %d, want 1 (the rest of the element applies)", len(bodies))
		}
		if _, sent := bodies[0]["password"]; sent {
			t.Error("the password must be left out")
		}
		if bodies[0]["descr"] != "a new description" {
			t.Errorf("the rest of the element must apply, body = %v", bodies[0])
		}
	})

	t.Run("one character different", func(t *testing.T) {
		users, groups := liveAccounts()
		users[8]["password"] = stored
		f := newFakeAccounts(t, users, groups)

		changed := stored[:len(stored)-1] + "Z"
		result := runGate(t, f, []opnapi.APIUserPayload{{Name: "nd-hm-plain", Password: changed}}, nil, false)

		if items := refusedItems(result); len(items) != 1 || items[0].Code != passwordIsHashCode {
			t.Errorf("items = %+v, want the hash refusal", items)
		}
		if f.wroteAnythingFor("user", "nd-hm-plain") {
			t.Error("a refused element reached OPNsense")
		}
	})

	t.Run("another user's hash", func(t *testing.T) {
		users, groups := liveAccounts()
		users[8]["password"] = stored // nd-hm-plain holds it, carol does not
		f := newFakeAccounts(t, users, groups)

		result := runGate(t, f, []opnapi.APIUserPayload{{Name: "carol", Password: stored}}, nil, false)

		if items := refusedItems(result); len(items) != 1 || items[0].Name != "carol" {
			t.Errorf("items = %+v, want carol refused: the exception is per user", items)
		}
	})

	t.Run("a new user", func(t *testing.T) {
		users, groups := liveAccounts()
		users[8]["password"] = stored
		f := newFakeAccounts(t, users, groups)

		result := runGate(t, f, []opnapi.APIUserPayload{{Name: "newbie", Password: stored}}, nil, false)
		if len(refusedItems(result)) != 1 || f.wroteAnythingFor("user", "newbie") {
			t.Errorf("a user that does not exist holds no hash to be identical to: %+v %v", result.Results, f.writes)
		}
	})
}

func TestUserPasswordIsHash_AppliesWhateverTheLocalPolicyAndClearance(t *testing.T) {
	for _, rejectDangerous := range []bool{false, true} {
		for _, cleared := range []bool{false, true} {
			users, groups := liveAccounts()
			f := newFakeAccounts(t, users, groups)

			result := runGate(t, f, []opnapi.APIUserPayload{{Name: "svc", Password: hashOf(t, "sha512"), SuperuserCleared: cleared}}, nil, rejectDangerous)

			if items := refusedItems(result); len(items) != 1 || items[0].Code != passwordIsHashCode {
				t.Errorf("reject=%v cleared=%v: items %+v, want the hash refusal", rejectDangerous, cleared, items)
			}
		}
	}
}

// TestUserPasswordIsHash_OneItemPerElement: an element that trips two checks is
// reported once, by the first to refuse it.
func TestUserPasswordIsHash_OneItemPerElement(t *testing.T) {
	cases := map[string]opnapi.APIUserPayload{
		"also takes over an administrator": {Name: "alice-admin", Password: hashOf(t, "bcrypt $2y$")},
		"also joins admins":                {Name: "svc", Password: hashOf(t, "bcrypt $2y$"), Groups: []string{"admins"}},
	}
	for name, user := range cases {
		t.Run(name, func(t *testing.T) {
			users, groups := liveAccounts()
			f := newFakeAccounts(t, users, groups)

			result := runGate(t, f, []opnapi.APIUserPayload{user}, nil, true)

			if n := len(refusedItems(result)); n != 1 || len(result.Errors) != 1 {
				t.Errorf("items %d, errors %d, want one of each: %+v", n, len(result.Errors), result.Results)
			}
			assertErrorHasMatchingResultItem(t, "two reasons", result.Errors, result.Results)
		})
	}
}

func TestUserPassword_APlaintextThatStartsWithADollarIsNotAHash(t *testing.T) {
	users, groups := liveAccounts()
	f := newFakeAccounts(t, users, groups)

	for _, pw := range []string{"$ecret-Passw0rd", "$2y$hash", "$6$not-a-hash", "$argon2id$nope"} {
		result := runGate(t, f, []opnapi.APIUserPayload{{Name: "u-" + pw[:3], Password: pw}}, nil, false)
		if len(refusedItems(result)) != 0 || !result.Success {
			t.Errorf("password %q is plaintext: %+v", pw, result)
		}
	}
}

func TestUserPassword_NewUserStillNeedsOne(t *testing.T) {
	users, groups := liveAccounts()
	f := newFakeAccounts(t, users, groups)

	result := runGate(t, f, []opnapi.APIUserPayload{{Name: "newbie"}}, nil, false)
	if result.Success || len(result.Errors) != 1 || !strings.Contains(result.Errors[0], "password required for new user") {
		t.Errorf("result = %+v, want the existing 'password required' failure", result)
	}
}

// argon2idOfPlainStart is what PHP's password_hash(PASSWORD_ARGON2ID) writes for
// "Pw-Plain-Start-1" with a light cost (m=1024, t=1, p=1), which is what OPNsense
// 26.7.5 and later store for a password they were sent. opnapi's tests hold the
// same kind of vector at PHP's default cost.
const (
	argon2idOfPlainStart     = "$argon2id$v=19$m=1024,t=1,p=1$TGs4dE55VkF3djkzNGhRYw$z06MQNK1uGsolWRD2kAFCa5GrIaBsRIcdS2VgpUFIZI"
	argon2idAskingForTooMuch = "$argon2id$v=19$m=524288,t=1,p=1$TGs4dE55VkF3djkzNGhRYw$z06MQNK1uGsolWRD2kAFCa5GrIaBsRIcdS2VgpUFIZI"
)

// TestUserPassword_SkippedWhenTheStoredHashVerifiesIt: OPNsense re-hashes every
// password it is sent, with a new salt each time, so an unchanged plaintext is not
// posted again. A stored bcrypt hash (OPNsense until 26.7.4) and a stored Argon2id
// hash (from 26.7.5) can be verified here; any other scheme is posted as before.
func TestUserPassword_SkippedWhenTheStoredHashVerifiesIt(t *testing.T) {
	const right = "the-right-password"
	good := bcryptOf(t, right)
	asPHP := "$2y$" + good[4:] // OPNsense stores $2y$, the same algorithm under another prefix
	long := strings.Repeat("x", 80)

	tests := []struct {
		name     string
		stored   interface{}
		password string
		posted   bool
	}{
		{"stored bcrypt verifies the plaintext", good, right, false},
		{"stored bcrypt with the $2y$ prefix PHP writes", asPHP, right, false},
		{"stored bcrypt of another password", bcryptOf(t, "another"), right, true},
		{"stored argon2id verifies the plaintext", argon2idOfPlainStart, "Pw-Plain-Start-1", false},
		{"stored argon2id of another password", argon2idOfPlainStart, right, true},
		{"stored argon2id asking for more than the agent will compute", argon2idAskingForTooMuch, "Pw-Plain-Start-1", true},
		{"stored sha512 cannot be verified", hashOf(t, "sha512"), right, true},
		{"stored sha256 cannot be verified", hashOf(t, "sha256"), right, true},
		{"nothing stored", "", right, true},
		{"a stored value that is not text", float64(7), right, true},
		{"the legacy $2x$ prefix is not trusted", "$2x$" + good[4:], right, true},
		{"a plaintext over bcrypt's 72 bytes is never compared", bcryptOf(t, long[:72]), long, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			users, groups := liveAccounts()
			users[8]["password"] = tt.stored // nd-hm-plain
			f := newFakeAccounts(t, users, groups)

			result := runGate(t, f, []opnapi.APIUserPayload{{Name: "nd-hm-plain", Password: tt.password, Descr: "changed"}}, nil, false)

			if !result.Success {
				t.Fatalf("unexpected failure: %v", result.Errors)
			}
			bodies := f.bodies["set user nd-hm-plain"]
			if len(bodies) != 1 {
				t.Fatalf("set calls = %d, want 1: the rest of the element applies either way", len(bodies))
			}
			pw, sent := bodies[0]["password"]
			if sent != tt.posted {
				t.Errorf("password sent = %v, want %v", sent, tt.posted)
			}
			if tt.posted && pw != tt.password {
				t.Errorf("password = %v, want the plaintext as authored", pw)
			}
			if bodies[0]["descr"] != "changed" {
				t.Errorf("the rest of the element must apply: %v", bodies[0])
			}
		})
	}
}

func TestUserPassword_NewUserPostsThePlaintext(t *testing.T) {
	users, groups := liveAccounts()
	f := newFakeAccounts(t, users, groups)

	runGate(t, f, []opnapi.APIUserPayload{{Name: "newbie", Password: "fresh-password"}}, nil, false)

	bodies := f.bodies["add user newbie"]
	if len(bodies) != 1 || bodies[0]["password"] != "fresh-password" {
		t.Errorf("add bodies = %v, want the plaintext", bodies)
	}
}

// TestUserPassword_TheStoredHashIsOnlyComputedForAnElementNothingRefused: telling
// an unchanged plaintext apart means hashing it again, which costs tens of
// milliseconds for bcrypt and more for Argon2id. An element that is going to be
// refused anyway, by any check, must not pay for it.
func TestUserPassword_TheStoredHashIsOnlyComputedForAnElementNothingRefused(t *testing.T) {
	const right = "the-right-password"
	stored := bcryptOf(t, right)

	calls := 0
	verify := storedPasswordVerifies
	storedPasswordVerifies = func(stored, plaintext string) bool {
		calls++
		return verify(stored, plaintext)
	}
	t.Cleanup(func() { storedPasswordVerifies = verify })

	tests := []struct {
		name         string
		user         opnapi.APIUserPayload
		rejectDanger bool
		wantRefused  bool
	}{
		{"refused for clearance", opnapi.APIUserPayload{Name: "alice-admin"}, false, true},
		{"refused for a same-name element", opnapi.APIUserPayload{Name: "nd-hm-plain", SnippetIndex: 1}, false, true},
		{"refused by the owner's policy", opnapi.APIUserPayload{Name: "nd-hm-plain", Priv: []string{"page-all"}, SuperuserCleared: true}, true, true},
		{"refused for a password that is a hash", opnapi.APIUserPayload{Name: "nd-hm-plain", Password: hashOf(t, "sha512")}, false, true},
		{"applied", opnapi.APIUserPayload{Name: "nd-hm-plain"}, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls = 0
			users, groups := liveAccounts()
			for _, u := range users {
				if u["name"] == "nd-hm-plain" || u["name"] == "alice-admin" {
					u["password"] = stored
				}
			}
			f := newFakeAccounts(t, users, groups)

			user := tt.user
			if user.Password == "" {
				user.Password = right
			}
			payload := []opnapi.APIUserPayload{user}
			if tt.name == "refused for a same-name element" {
				payload = append(payload, opnapi.APIUserPayload{Name: "nd-hm-plain", Password: right, SuperuserCleared: true, SnippetIndex: 0})
			}
			result := runGate(t, f, payload, nil, tt.rejectDanger)

			refused := len(refusedItems(result)) > 0
			if refused != tt.wantRefused {
				t.Fatalf("refused = %v, want %v: %+v", refused, tt.wantRefused, result.Results)
			}
			want := 0
			if !tt.wantRefused {
				want = 1
			}
			if tt.name == "refused for a same-name element" {
				want = 1 // the cleared twin is applied and verified once
			}
			if calls != want {
				t.Errorf("stored hash computed %d times, want %d", calls, want)
			}
		})
	}
}
