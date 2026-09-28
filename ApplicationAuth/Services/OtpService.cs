using System.Security.Cryptography;
using ApplicationAuth.Data;
using ApplicationAuth.Models;
using Microsoft.EntityFrameworkCore;

namespace ApplicationAuth.Services;

public class OtpService : IOtpService
{
    private readonly ApplicationDbContext _context;
    private readonly IConfiguration _configuration;

    public OtpService(ApplicationDbContext context, IConfiguration configuration)
    {
        _context = context;
        _configuration = configuration;
    }

    public async Task<string> GenerateOtpAsync(string email, OtpPurpose purpose, string userId = "")
    {
        var normalizedEmail = NormalizeEmail(email);
        var cooldownSeconds = _configuration.GetValue<int>("Otp:ResendCooldownSeconds", 60);
        var cooldownStart = DateTime.UtcNow.AddSeconds(-Math.Max(0, cooldownSeconds));
        if (cooldownSeconds > 0 && await _context.OtpVerifications.AnyAsync(x =>
                x.Email == normalizedEmail && x.Purpose == purpose && x.CreatedAt >= cooldownStart))
        {
            throw new OtpCooldownException();
        }

        var otpCode = GenerateNumericOtp();
        var otpHash = HashOtp(otpCode);
        var otpExpiryMinutes = _configuration.GetValue<int>("Otp:ExpiryMinutes", 5);

        await InvalidateExistingOtpsAsync(normalizedEmail, purpose);

        var otp = new OtpVerification
        {
            UserId = string.IsNullOrWhiteSpace(userId) ? null : userId,
            Email = normalizedEmail,
            Purpose = purpose,
            OtpHash = otpHash,
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.AddMinutes(otpExpiryMinutes),
            AttemptsUsed = 0,
            MaxAttempts = _configuration.GetValue<int>("Otp:MaxAttempts", 5),
            IsUsed = false,
            IsRevoked = false
        };

        _context.OtpVerifications.Add(otp);
        await _context.SaveChangesAsync();

        return otpCode;
    }

    public async Task<bool> VerifyOtpAsync(string email, string otpCode, OtpPurpose purpose)
    {
        var normalizedEmail = NormalizeEmail(email);
        var otp = await _context.OtpVerifications
            .Where(x => x.Email == normalizedEmail && x.Purpose == purpose && !x.IsRevoked)
            .OrderByDescending(x => x.CreatedAt)
            .FirstOrDefaultAsync();

        if (otp == null)
        {
            return false;
        }

        if (otp.IsUsed || otp.ExpiresAt < DateTime.UtcNow)
        {
            otp.IsRevoked = true;
            await _context.SaveChangesAsync();
            return false;
        }

        if (otp.AttemptsUsed >= otp.MaxAttempts)
        {
            otp.IsRevoked = true;
            await _context.SaveChangesAsync();
            return false;
        }

        otp.AttemptsUsed++;

        if (!IsHashMatch(otpCode, otp.OtpHash))
        {
            if (otp.AttemptsUsed >= otp.MaxAttempts)
            {
                otp.IsRevoked = true;
            }

            await _context.SaveChangesAsync();
            return false;
        }

        otp.IsUsed = true;
        otp.VerifiedAt = DateTime.UtcNow;
        await _context.SaveChangesAsync();
        return true;
    }

    public async Task<bool> IsOtpStillValidAsync(string email, OtpPurpose purpose)
    {
        var normalizedEmail = NormalizeEmail(email);
        var otp = await _context.OtpVerifications
            .Where(x => x.Email == normalizedEmail && x.Purpose == purpose && !x.IsUsed && !x.IsRevoked)
            .OrderByDescending(x => x.CreatedAt)
            .FirstOrDefaultAsync();

        return otp is not null && otp.ExpiresAt > DateTime.UtcNow;
    }

    public async Task InvalidateExistingOtpsAsync(string email, OtpPurpose purpose)
    {
        var normalizedEmail = NormalizeEmail(email);
        var existing = await _context.OtpVerifications
            .Where(x => x.Email == normalizedEmail && x.Purpose == purpose && !x.IsUsed && !x.IsRevoked)
            .ToListAsync();

        foreach (var item in existing)
        {
            item.IsRevoked = true;
        }

        if (existing.Count > 0)
        {
            await _context.SaveChangesAsync();
        }
    }

    private static string GenerateNumericOtp()
    {
        var random = RandomNumberGenerator.GetInt32(0, 1_000_000);
        return random.ToString("D6");
    }

    private string HashOtp(string value)
    {
        return Convert.ToHexString(HMACSHA256.HashData(GetHmacKey(), System.Text.Encoding.UTF8.GetBytes(value)));
    }

    private bool IsHashMatch(string value, string expectedHash)
    {
        try
        {
            var expected = Convert.FromHexString(expectedHash);
            var actual = HMACSHA256.HashData(GetHmacKey(), System.Text.Encoding.UTF8.GetBytes(value));
            return CryptographicOperations.FixedTimeEquals(actual, expected);
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private byte[] GetHmacKey()
    {
        var configuredKey = _configuration["Otp:HmacKey"];
        if (string.IsNullOrWhiteSpace(configuredKey))
        {
            throw new InvalidOperationException("OTP signing is not configured.");
        }

        try
        {
            var key = Convert.FromBase64String(configuredKey);
            if (key.Length < 32)
            {
                throw new InvalidOperationException("OTP signing is not configured.");
            }

            return key;
        }
        catch (FormatException)
        {
            throw new InvalidOperationException("OTP signing is not configured.");
        }
    }

    private static string NormalizeEmail(string email) => email.Trim().ToUpperInvariant();
}

public sealed class OtpCooldownException : Exception;
