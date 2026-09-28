# ApplicationAuth

## Production configuration

Configure these values in Azure App Service settings, not in source control:

- `ConnectionStrings__DefaultConnection` for the existing Azure SQL database.
- `Email__SmtpHost`, `Email__SmtpPort` (STARTTLS, normally 587), `Email__Username`, `Email__Password`, and `Email__FromAddress` for authenticated SMTP delivery.
- `Otp__HmacKey` as a Base64-encoded key containing at least 32 random bytes.
- `ASPNETCORE_ENVIRONMENT=Production`.

Production startup fails when the SQL, SMTP, or OTP-signing settings are missing. OTP codes are never logged or included in responses. The application does not apply migrations at startup; apply the reviewed migrations deliberately during deployment.