# Free service keys

All keys go in `.env` (copied from `.env.example`). The credential broker is the only process that reads them. The demo works with no keys via the phone simulator and built-in on-call page.

## Twilio (outbound and inbound voice)

1. Create a free trial account at https://console.twilio.com
2. Verify `ONCALL_PHONE_NUMBER` under Phone Numbers > Verified Caller IDs (trial can only call verified numbers).
3. Get a trial phone number under Phone Numbers > Manage > Buy a number. Put it in `TWILIO_FROM_NUMBER`.
4. Copy Account SID and Auth Token into `TWILIO_ACCOUNT_SID` and `TWILIO_AUTH_TOKEN`.
5. Set `ONCALL_PIN` to a short numeric PIN you will type on the keypad.
6. `make demo` starts a Cloudflare quick tunnel when these keys are present and registers the webhook URL with Twilio.

Trial plays a short notice before your message. That is expected.

## PagerDuty (Events API v2)

1. Sign up at https://developer.pagerduty.com/sign-up
   - If a personal email domain is rejected, use a school or work email.
2. Create a service in the developer instance.
3. Add an Events API v2 integration on that service.
4. Copy the integration / routing key into `PAGERDUTY_ROUTING_KEY`.

No public webhook is required. Events are outbound HTTPS only.

## Telegram (optional)

1. Talk to `@BotFather` in Telegram, create a bot, copy the token to `TELEGRAM_BOT_TOKEN`.
2. Start a chat with the bot, then find your chat id (for example via `@userinfobot` or the Bot API `getUpdates`) and set `TELEGRAM_CHAT_ID`.
3. Long polling only; no public URL.

## Without keys

Leave the variables empty. The frontend phone simulator and built-in on-call incident page cover the same flows for the demo and for `make e2e`.
