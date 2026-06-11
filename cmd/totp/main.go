package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"hash"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

func main() {
	if len(os.Args) != 2 {
		printUsage()
		os.Exit(1)
	}

	u, err := url.Parse(os.Args[1])
	if err != nil || u.Scheme != "otpauth" {
		fmt.Fprintln(os.Stderr, "invalid otpauth URI")
		os.Exit(1)
	}

	q := u.Query()
	secret := strings.ToUpper(strings.TrimSpace(q.Get("secret")))
	if secret == "" {
		fmt.Fprintln(os.Stderr, "missing secret in URI")
		os.Exit(1)
	}

	digits := 6
	if d, err := strconv.Atoi(q.Get("digits")); err == nil {
		digits = d
	}

	period := 30
	if p, err := strconv.Atoi(q.Get("period")); err == nil {
		period = p
	}

	algo := "sha1"
	if a := q.Get("algorithm"); a != "" {
		algo = strings.ToLower(a)
	}

	code, err := generateTOTP(secret, digits, period, algo)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(code)
}

func generateTOTP(secret string, digits, period int, algo string) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		key, err = base32.StdEncoding.DecodeString(secret)
		if err != nil {
			return "", fmt.Errorf("invalid secret: %w", err)
		}
	}

	counter := time.Now().Unix() / int64(period)
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(counter))

	var h func() hash.Hash
	switch algo {
	case "sha256":
		h = sha256.New
	case "sha512":
		h = sha512.New
	default:
		h = sha1.New
	}

	mac := hmac.New(h, key)
	mac.Write(buf)
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0xf
	code := int32(sum[offset])&0x7f<<24 |
		int32(sum[offset+1])&0xff<<16 |
		int32(sum[offset+2])&0xff<<8 |
		int32(sum[offset+3])&0xff

	mod := int32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}

	return fmt.Sprintf("%0*d", digits, code%mod), nil
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "Usage: totp OTPAUTH_URI")
	fmt.Fprintln(os.Stderr, "\nExample:")
	fmt.Fprintln(os.Stderr, "  totp 'otpauth://totp?secret=JBSWY3DPEHPK3PXP&digits=6&period=30'")
}
