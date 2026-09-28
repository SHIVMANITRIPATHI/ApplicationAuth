using System.ComponentModel.DataAnnotations;

namespace ApplicationAuth.ViewModels;

public class ForgotPasswordViewModel
{
    [Required]
    [Display(Name = "Email or Username")]
    public string UserNameOrEmail { get; set; } = string.Empty;
}
