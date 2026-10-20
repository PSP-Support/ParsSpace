# ParsSpace
## V14.2 fixes
- Bot token/API key save now waits for durable state write before returning; UI shows the masked saved-token state after refresh.
- Bot internal user create/delete calls use Railway `$PORT` instead of hard-coded 8080.
- Added panel-side ticket reply, close/reopen actions.
- Replaced prompt-based sales-plan creation with a form modal including inbound and concurrent-user selection.
- Simplified required-channel entry with add/remove controls and t.me normalization.
- Added multi-provider server country detection fallback.
- Managed TLS+WS configs prefer Railway's canonical public hostname as the dial address when available while retaining panel Host/SNI, improving mobile/DDNS compatibility.
