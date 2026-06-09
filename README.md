# totp-cli

A minimal command-line TOTP code generator. Accepts an `otpauth://` URI and prints the current one-time password.

## Install

```bash
go install github.com/nairvarun/totp-cli/cmd/totp@latest
```

## Usage

```bash
totp 'otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP&digits=6&period=30'
```

Or with the URI stored in an environment variable:

```bash
export MY_SERVICE_OTP_URI='otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP&digits=6&period=30'
totp "$MY_SERVICE_OTP_URI"
```

Supports SHA1, SHA256, and SHA512 algorithms, configurable digit counts, and configurable periods.

## License

MIT
