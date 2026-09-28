using ApplicationAuth.Models;

namespace ApplicationAuth.Services;

public interface IOtpService
{
    Task<string> GenerateOtpAsync(string email, OtpPurpose purpose, string userId = "");
    Task<bool> VerifyOtpAsync(string email, string otpCode, OtpPurpose purpose);
    Task<bool> IsOtpStillValidAsync(string email, OtpPurpose purpose);
    Task InvalidateExistingOtpsAsync(string email, OtpPurpose purpose);
}
