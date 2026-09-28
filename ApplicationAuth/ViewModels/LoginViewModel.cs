using System.ComponentModel.DataAnnotations;

namespace ApplicationAuth.ViewModels;

public class LoginViewModel
{
    [Required]
    [Display(Name = "Username or Email")]
    public string UserNameOrEmail { get; set; } = string.Empty;

    [DataType(DataType.Password)]
    [Display(Name = "Password")]
    public string? Password { get; set; }

    [Display(Name = "OTP")]
    [RegularExpression("\\d{6}", ErrorMessage = "OTP must be 6 digits.")]
    public string? OtpCode { get; set; }

    public bool UseOtpLogin { get; set; }

    public bool RememberMe { get; set; }
}
