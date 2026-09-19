# Aurelia

A response manipulation lab. Four exercises that reproduce real-world bugs I've found on production financial apps: the server makes a decision, ships the wrong verdict in the response, and the client believes it.

Run it locally, proxy it through Burp/Caido/ZAP, and rewrite the responses.

## Labs

| # | Name | What the client trusts | What the server actually did |
|---|---|---|---|
| 1 | Status Code Flip | HTTP status `200` | Rejected the login, minted a JWT anyway |
| 2 | Envelope + Body Trust | `unlocked: true` flag | Denied the request, shipped a session token |
| 3 | OTP Response Manipulation | `verified: true` flag | Wrong code, but returned a valid sessionToken |
| 4 | Device Binding Bypass | `match: true` flag | Unknown device, but returned a working grant |

There is also an untracked vulnerability: the server checks `checkRevocation: false` so signed-out tokens still work. No lab page for it, but you can reproduce it through the normal sign-in/sign-out flow.

## Setup

```
npm install
npm start
```

Server runs on `http://127.0.0.1:3000`.

## Proxy

All requests go through your browser's proxy settings or Burp. The built-in interceptor is OFF by default. Use your own proxy for the labs.

## Users

| Email | Password | OTP | Device ID |
|---|---|---|---|
| alice@velare.io | Aurora!2026 | 603391 | mbp7f3 |
| nathan@velare.io | Aurora!2026 | 772014 | xps12a |
| admin@velare.io | Aurora!2026 | 915562 | lob9c |

## How to Use

1. Open `http://127.0.0.1:3000` in your browser (proxy it through Burp).
2. Pick a lab from the index.
3. Send the request through your proxy.
4. Rewrite the response (status code, flags, whatever the lab description says).
5. Forward it and see what the client does.

## What This Is Not

This is not a CTF. There are no flags to capture. The goal is to understand a bug class: when the client trusts a response the attacker can rewrite, authentication breaks.

## Built With

Just Node.js. No frameworks, no dependencies.
