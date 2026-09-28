using System.Net;
using System.Net.Mail;

namespace ApplicationAuth.Services;

public class EmailService : IEmailService
{
    private readonly ILogger<EmailService> _logger;
    private readonly IConfiguration _configuration;

    public EmailService(ILogger<EmailService> logger, IConfiguration configuration)
    {
        _logger = logger;
        _configuration = configuration;
    }

    public Task SendOtpAsync(string toEmail, string otpCode, string purpose)
    {
        return SendEmailAsync(toEmail, "Your ApplicationAuth verification code",
            $"Your ApplicationAuth {purpose} OTP is: {otpCode}\n\nThis code expires in {_configuration.GetValue<int>("Otp:ExpiryMinutes", 5)} minutes.");
    }

    public Task SendAccountApprovalAsync(string toEmail, bool approved) =>
        SendEmailAsync(toEmail, "ApplicationAuth account status",
            approved ? "Your ApplicationAuth account has been approved." : "Your ApplicationAuth account was not approved.");

    private async Task SendEmailAsync(string toEmail, string subject, string body)
    {
        var host = _configuration["Email:SmtpHost"];
        var username = _configuration["Email:Username"];
        var password = _configuration["Email:Password"];
        var fromAddress = _configuration["Email:FromAddress"];
        var port = _configuration.GetValue<int>("Email:SmtpPort", 587);

        if (string.IsNullOrWhiteSpace(host) || string.IsNullOrWhiteSpace(username)
            || string.IsNullOrWhiteSpace(password) || string.IsNullOrWhiteSpace(fromAddress)
            || port is < 1 or > 65535 || !MailAddress.TryCreate(fromAddress, out _)
            || !MailAddress.TryCreate(toEmail, out _))
        {
            throw new EmailDeliveryException();
        }

        try
        {
            using var message = new MailMessage(fromAddress, toEmail, subject, body);
            using var client = new SmtpClient(host, port)
            {
                EnableSsl = true,
                Credentials = new NetworkCredential(username, password),
                DeliveryMethod = SmtpDeliveryMethod.Network,
                Timeout = 15000
            };
            await client.SendMailAsync(message);
        }
        catch (Exception exception)
        {
            _logger.LogError("SMTP delivery failed. Error type: {ErrorType}", exception.GetType().Name);
            throw new EmailDeliveryException();
        }
    }
}

public sealed class EmailDeliveryException : Exception;
