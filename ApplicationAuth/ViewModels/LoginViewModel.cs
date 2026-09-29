using System.ComponentModel.DataAnnotations;

namespace ApplicationAuth.ViewModels;

public class LoginViewModel
{
    [Required]
    [Display(Name = "Username")]
    public string UserName { get; set; } = string.Empty;

    [Required]
    [DataType(DataType.Password)]
    [Display(Name = "Password")]
    public string? Password { get; set; }

    [Required]
    [Display(Name = "CAPTCHA")]
    public string CaptchaAnswer { get; set; } = string.Empty;

    public string? ReturnUrl { get; set; }

    public string LoginAs { get; set; } = "User";

    public bool RememberMe { get; set; }

}
