namespace ApplicationAuth.Models;

public enum OtpPurpose
{
    Registration = 0,
    Login = 1,
    PasswordReset = 2
}

public class OtpVerification
{
    public int Id { get; set; }

    public string? UserId { get; set; }

    public string Email { get; set; } = string.Empty;

    public OtpPurpose Purpose { get; set; }

    public string OtpHash { get; set; } = string.Empty;

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public DateTime ExpiresAt { get; set; }

    public int AttemptsUsed { get; set; }

    public int MaxAttempts { get; set; } = 5;

    public bool IsUsed { get; set; }

    public DateTime? VerifiedAt { get; set; }

    public bool IsRevoked { get; set; }

    public virtual ApplicationUser? User { get; set; }
}
