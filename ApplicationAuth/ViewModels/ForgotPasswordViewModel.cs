using System.ComponentModel.DataAnnotations;

namespace ApplicationAuth.ViewModels;

public class ForgotPasswordViewModel
{
    [Required]
    [EmailAddress]
    [Display(Name = "Email")]
    public string Email { get; set; } = string.Empty;
}
