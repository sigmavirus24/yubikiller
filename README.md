# Yubikiller

I've recently started using a YubiKey 5 Nano but have been accidentally
pressing it while carrying my laptop around. If captured in public, those OTP
codes can be used to access the accounts I'm using my YubiKey for.

I'd prefer to invalidate those OTP codes and have something simple for doing
so.

With Python 3 as the default `python` on one's system, you could do:

```
curl "https://api.yubico.com/wsapi/2.0/verify?id=1&nonce=$(python -c 'import secrets; print(secrets.token_hex(16))')&otp=$OTP"
```

But who's going to remember that? And making a bash script or shell alias for
it does not inherently make it easy to install or use.

Instead, I wrote this small tool that can be expanded upon and will check the
fields returned by Yubico's API.

## Installation

```
go install github.com/sigmavirus24/yubikiller/cmd/yubikiller
```

## Usage

```
yubikiller <OTP>
```

## License

3-Clause BSD License (for more details see [the OSI][]), also known as
BSD-3-Clause (SPDX identifier)



<!-- links -->
[the OSI]: https://opensource.org/licenses/BSD-3-Clause
