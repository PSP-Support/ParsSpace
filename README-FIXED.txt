Pars Space UI compatibility fix

The previous v2 package had a frontend/backend API mismatch: the new HTML called /api/pars/v1/* while the included main.py did not expose those routes. This package aligns the new UI with the actual API routes present in main.py.

Replaced:
- static/index.html
- main.py is kept from the original deploy package

Important:
- Current node API in this compatible build uses the existing panel API key with psp_ prefix.
- Administrator username is not changed by this build; password change remains available.
- A fully independent Pars Space API v1 still requires a backend refactor and should not be considered implemented by this compatibility package.
