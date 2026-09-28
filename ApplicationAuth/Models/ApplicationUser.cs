using Microsoft.AspNetCore.Identity;

namespace ApplicationAuth.Models;

public enum UserAccountStatus
{
    Pending = 0,
    Approved = 1,
    Rejected = 2,
    Suspended = 3
}

public class ApplicationUser : IdentityUser
{
    [PersonalData]
    public string FullName { get; set; } = string.Empty;

    public bool IsApproved { get; set; }

    public bool IsActive { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public DateTime? UpdatedAt { get; set; }

    public DateTime? LastLoginAt { get; set; }

    public UserAccountStatus AccountStatus { get; set; } = UserAccountStatus.Pending;
}
