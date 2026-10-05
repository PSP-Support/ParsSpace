Pars Space v6

- More dynamic liquid-glass dashboard styling.
- Users and Config Test are separate tabs.
- Removed the Subscriptions navigation tab and its dashboard quick action.
- Per-user subscription URL remains /link/{config_uuid} and now also works with the Pars Space graphical subscription page.
- User management: edit, enable/disable, delete, reset traffic, QR code, personal subscription copy.
- Config Test tab with independent config test and speed test.
- VMess/Trojan Reality links are generated as their own protocols instead of being downgraded to VLESS.
- Xray Reality inbounds can serve VMess/Trojan natively when Xray is present.
- Fixed Trojan Xray client password lookup.
- Native TLS VMess/Trojan only starts when XRAY_CERT_FILE and XRAY_KEY_FILE exist.
- Login and Subscription pages received additional glass motion effects and mobile-safe layout.
- All generated config remarks use Pars Space branding.
