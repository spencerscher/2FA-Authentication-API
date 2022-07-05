# Multi-Factor-Authentication
Multi-Factor Authentication API that allows users to create accounts and enable 2FA. The current TOTP 2FA implementation will generate unique QR codes to scan into a multi-factor app of choice (Google Authenticator).

This multi-factor API uses JWTs to authenticate users on protected endpoints. Each JWT (1 hr expiry time) is signed with the respective users' hashed password in order to invalidate any non-expired JWTs on a password reset. Therefore, when a password is reset, all non-expired JWTs for a particular account will be invalidated as the signer has now changed for that account.

This API uses MongoDB as a database. Please add your MongoDB connection URL into `db/db.js`.

**Installation and Running API**
1. `npm install`.
2. `npm start`.

**Routes**<br />
`/account/register` - Allows the user to register for an account.<br />
`/account/login` - Allows the user to log in to an account.<br />
`/account/reset-password` - Sends a unique password reset link to the email attached to the account. Tokens are valid for 1 hour.<br />
`/account/reset-password/:token` - Resets the password on the account.<br />
`/account/2fa/enable` - Enables Two-Factor Authentication on an account.<br />
`/account/2fa/disable` - Disables Two-Factor Authentication on an account.<br />
`/account/authenticate` - Requires the user to provide the OTP if 2FA is enabled on their account in order to receive a full-scope JWT.
