using System.ComponentModel.DataAnnotations;

namespace ApplicationAuth.ViewModels;

public class LoginViewModel
{
    [Display(Name = "Email Address")]
    [EmailAddress]
    public string Email { get; set; } = string.Empty;

    [Required]
    [Display(Name = "Email or Username")]
    public string UserNameOrEmail { get; set; } = string.Empty;

    [DataType(DataType.Password)]
    [Display(Name = "Password")]
    public string? Password { get; set; }

    [Display(Name = "OTP")]
    [RegularExpression("\\d{6}", ErrorMessage = "OTP must be 6 digits.")]
    public string? OtpCode { get; set; }

    public string LoginAs { get; set; } = "User";

    public bool RememberMe { get; set; }

    public bool ShowOtpSection { get; set; }
}
