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

Supports SHA1, SHA256, and SHA512 algorithms, configurable digit counts, and configurable periods.

## License

MIT
