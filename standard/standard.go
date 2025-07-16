package standard

import (
	"crypto/sha512"
	"encoding/base64"
	"hash"
)

// HashAlgorithm is the algorithm used for hashing passwords.
const HashAlgorithm = "SHA512-384"

// SaltLength is the length of the salt used in password hashing.
const SaltLength = 24

// Encoding is the encoding used for storing passwords.
const Encoding = "base64URL"

// CookieLength is the length of the cookie secret in bytes.
const CookieLength = 72

func NewHash() hash.Hash {
	return sha512.New384()
}

func NewEncoder() *base64.Encoding {
	return base64.URLEncoding
}
