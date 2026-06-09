package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"flag"
	"fmt"
	"hash"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type TOTPConfig struct {
	secret string
	digits int
	period int
	algo   string
}

func main() {
	flag.Parse()

	if flag.NArg() != 1 {
		printUsage()
		os.Exit(1)
	}

	cfg := TOTPConfig{digits: 6, period: 30, algo: "sha1"}
	parseOTPAuthURI(flag.Arg(0), &cfg)

	if cfg.secret == "" {
		printUsage()
		os.Exit(1)
	}

	fmt.Print(generateTOTP(cfg))
}

func parseOTPAuthURI(rawURI string, cfg *TOTPConfig) {
	u, err := url.Parse(rawURI)
	if err != nil {
		return
	}
	q := u.Query()
	cfg.secret = strings.ToUpper(strings.TrimSpace(q.Get("secret")))

	if d, err := strconv.Atoi(q.Get("digits")); err == nil {
		cfg.digits = d
	}

	if p, err := strconv.Atoi(q.Get("period")); err == nil {
		cfg.period = p
	}

	if a := q.Get("algorithm"); a != "" {
		cfg.algo = strings.ToLower(a)
	}
}

func generateTOTP(cfg TOTPConfig) string {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(cfg.secret))
	if err != nil {
		// try with padding
		key, err = base32.StdEncoding.DecodeString(strings.ToUpper(cfg.secret))
		if err != nil {
			return ""
		}
	}

	counter := time.Now().Unix() / int64(cfg.period)

	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(counter))

	var h func() hash.Hash
	switch cfg.algo {
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
	code := (int32(sum[offset])&0x7f)<<24 |
		(int32(sum[offset+1])&0xff)<<16 |
		(int32(sum[offset+2])&0xff)<<8 |
		int32(sum[offset+3])&0xff

	mod := 1
	for i := 0; i < cfg.digits; i++ {
		mod *= 10
	}

	return fmt.Sprintf("%0*d", cfg.digits, code%int32(mod))
}


func printUsage() {
	fmt.Fprintf(os.Stderr, "Usage: totp OTPAUTH_URI\n")
	fmt.Fprintf(os.Stderr, "\nExample:\n")
	fmt.Fprintf(os.Stderr, "  totp 'otpauth://totp?secret=JBSWY3DPEHPK3PXP&digits=6&period=30'\n")
}
