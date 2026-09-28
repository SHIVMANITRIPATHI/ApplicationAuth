namespace ApplicationAuth.Services;

public interface IEmailService
{
    Task SendOtpAsync(string toEmail, string otpCode, string purpose);
    Task SendAccountApprovalAsync(string toEmail, bool approved);
}
