package opnapi

import "regexp"

// CryptHashShapePattern is the full shape of a password hash: the crypt(3)
// strings OPNsense's PHP and FreeBSD crypt() emit, and the Argon2 PHC strings
// PHP's PASSWORD_ARGON2ID emits.
//
//	bcrypt   $2a$ $2b$ $2x$ $2y$, a two-digit cost 04-31, then 53 characters
//	SHA-512  $6$, optional rounds=N$, a salt of 0-16 characters, then 86
//	SHA-256  $5$, optional rounds=N$, a salt of 0-16 characters, then 43
//	MD5      $1$, a salt of 0-8 characters, then 22
//	Argon2   $argon2id$ $argon2i$ $argon2d$, v=N, then m=N,t=N,p=N in that
//	         order, a salt of 11 or more characters, then a tag of 6 or more
//
// The text is the shared one, copied from NDDataModels' CRYPT_HASH_SHAPE_PATTERN
// and held equal to testdata/crypt-hash-shape/vectors.json. It carries no
// anchor: IsCryptHashShaped wraps it in a full match.
const CryptHashShapePattern = `\$2[abxy]\$(?:0[4-9]|[12][0-9]|3[01])\$[./A-Za-z0-9]{53}` +
	`|\$6\$(?:rounds=[0-9]+\$)?[./A-Za-z0-9]{0,16}\$[./A-Za-z0-9]{86}` +
	`|\$5\$(?:rounds=[0-9]+\$)?[./A-Za-z0-9]{0,16}\$[./A-Za-z0-9]{43}` +
	`|\$1\$[./A-Za-z0-9]{0,8}\$[./A-Za-z0-9]{22}` +
	`|\$argon2(?:id|i|d)\$v=[0-9]+\$m=[0-9]+,t=[0-9]+,p=[0-9]+` +
	`\$[A-Za-z0-9+/]{11,}\$[A-Za-z0-9+/]{6,}`

var cryptHashShape = regexp.MustCompile(`\A(?:` + CryptHashShapePattern + `)\z`)

// IsCryptHashShaped reports whether value, whole and unstripped, has the shape
// of a password hash. Shape only: nothing is verified, and a plaintext that
// merely starts with "$", contains a hash-like prefix or has stray whitespace is
// not a hash.
func IsCryptHashShaped(value string) bool {
	return cryptHashShape.MatchString(value)
}
