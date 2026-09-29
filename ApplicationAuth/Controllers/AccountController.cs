using System.Security.Cryptography;
using ApplicationAuth.Models;
using ApplicationAuth.Services;
using ApplicationAuth.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace ApplicationAuth.Controllers;

public class AccountController : Controller
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly IOtpService _otpService;
    private readonly IEmailService _emailService;
    private readonly ILogger<AccountController> _logger;

    public AccountController(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        IOtpService otpService,
        IEmailService emailService,
        ILogger<AccountController> logger)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _otpService = otpService;
        _emailService = emailService;
        _logger = logger;
    }

    [HttpGet]
    public IActionResult Register()
    {
        CreateCaptcha(RegistrationCaptchaSessionKey);
        return View(new RegisterViewModel());
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    [EnableRateLimiting("otp")]
    public async Task<IActionResult> Register(RegisterViewModel model)
    {
        if (!ValidateCaptcha(RegistrationCaptchaSessionKey, model.CaptchaAnswer))
        {
            ModelState.AddModelError(nameof(model.CaptchaAnswer), "The CAPTCHA is incorrect or expired.");
        }

        if (!ModelState.IsValid)
        {
            return RegistrationFailure(model);
        }

        var normalizedEmail = model.Email.Trim();
        var normalizedUserName = model.UserName.Trim();

        if (await _userManager.FindByEmailAsync(normalizedEmail) is not null)
        {
            ModelState.AddModelError(nameof(RegisterViewModel.Email), "An account with this email already exists.");
            return RegistrationFailure(model);
        }

        if (await _userManager.FindByNameAsync(normalizedUserName) is not null)
        {
            ModelState.AddModelError(nameof(RegisterViewModel.UserName), "This username is already taken.");
            return RegistrationFailure(model);
        }

        var user = new ApplicationUser
        {
            UserName = normalizedUserName,
            Email = normalizedEmail,
            FullName = model.FullName.Trim(),
            IsApproved = false,
            IsActive = false,
            AccountStatus = UserAccountStatus.Pending,
            CreatedAt = DateTime.UtcNow
        };

        var result = await _userManager.CreateAsync(user, model.Password);
        if (!result.Succeeded)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }

            return RegistrationFailure(model);
        }

        await _userManager.AddToRoleAsync(user, "User");

        return RedirectToAction(nameof(RegistrationSubmitted));
    }

    [HttpGet]
    public IActionResult RegistrationSubmitted()
    {
        return View();
    }

    [HttpGet]
    public IActionResult Login(string? returnUrl = null)
    {
        var model = new LoginViewModel { LoginAs = "User", ReturnUrl = returnUrl };
        CreateCaptcha(LoginCaptchaSessionKey);
        return View(model);
    }

    [HttpGet]
    public IActionResult RegistrationCaptchaImage() => CreateCaptchaImage(RegistrationCaptchaSessionKey);

    [HttpGet]
    public IActionResult LoginCaptchaImage() => CreateCaptchaImage(LoginCaptchaSessionKey);

    [HttpPost]
    [ValidateAntiForgeryToken]
    [EnableRateLimiting("otp")]
    public async Task<IActionResult> Login(LoginViewModel model)
    {
        var loginAs = model.LoginAs is "Admin" or "User" ? model.LoginAs : "User";
        if (model.LoginAs is not ("Admin" or "User"))
        {
            ModelState.AddModelError(string.Empty, "Invalid username or password.");
        }

        if (!ValidateCaptcha(LoginCaptchaSessionKey, model.CaptchaAnswer))
        {
            ModelState.AddModelError(nameof(model.CaptchaAnswer), "The CAPTCHA is incorrect or expired.");
        }

        if (!ModelState.IsValid)
        {
            return LoginFailure(model, loginAs);
        }

        model.LoginAs = loginAs;
        var user = await _userManager.FindByNameAsync(model.UserName.Trim());
        if (user is null)
        {
            ModelState.AddModelError(string.Empty, "Invalid username or password.");
            return LoginFailure(model, loginAs);
        }

        var passwordResult = await _signInManager.CheckPasswordSignInAsync(user, model.Password!, lockoutOnFailure: true);
        if (!passwordResult.Succeeded)
        {
            ModelState.AddModelError(string.Empty, "Invalid username or password.");
            return LoginFailure(model, loginAs);
        }

        if (loginAs == "User")
        {
            var message = user.AccountStatus == UserAccountStatus.Pending
                ? "Your account is pending Admin approval. Please wait until an Admin approves your account."
                : user.AccountStatus == UserAccountStatus.Rejected
                    ? "Your account has been rejected. Please contact the administrator."
                    : !user.IsActive || user.AccountStatus == UserAccountStatus.Suspended
                        ? "Your account is currently inactive. Please contact the administrator."
                        : !user.IsApproved || user.AccountStatus != UserAccountStatus.Approved
                            ? "Your account is pending Admin approval. Please wait until an Admin approves your account."
                            : null;
            if (message is not null)
            {
                ModelState.AddModelError(string.Empty, message);
                return LoginFailure(model, loginAs);
            }
        }
        else if (!user.IsApproved || !user.IsActive || user.AccountStatus != UserAccountStatus.Approved)
        {
            ModelState.AddModelError(string.Empty, "Invalid username or password.");
            return LoginFailure(model, loginAs);
        }

        if (!await _userManager.IsInRoleAsync(user, loginAs))
        {
            ModelState.AddModelError(string.Empty, "Invalid username or password.");
            return LoginFailure(model, loginAs);
        }

        user.LastLoginAt = DateTime.UtcNow;
        user.UpdatedAt = DateTime.UtcNow;
        var updateResult = await _userManager.UpdateAsync(user);
        if (!updateResult.Succeeded)
        {
            ModelState.AddModelError(string.Empty, "Sign-in could not be completed. Please try again.");
            return LoginFailure(model, loginAs);
        }

        await _signInManager.SignInAsync(user, model.RememberMe);
        return await RedirectToLocal(model.ReturnUrl, user);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    [Authorize]
    public async Task<IActionResult> Logout()
    {
        await _signInManager.SignOutAsync();
        return RedirectToAction(nameof(Login));
    }

    [HttpGet]
    public IActionResult ForgotPassword()
    {
        return View(new ForgotPasswordViewModel());
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    [EnableRateLimiting("otp")]
    public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var email = model.Email.Trim();
        var user = await _userManager.FindByEmailAsync(email);

        if (user is null)
        {
            TempData["SuccessMessage"] = "If the account exists, a password reset OTP has been sent.";
            return RedirectToAction(nameof(ForgotPassword));
        }

        try
        {
            var otpCode = await _otpService.GenerateOtpAsync(user.Email!, OtpPurpose.PasswordReset, user.Id);
            await _emailService.SendOtpAsync(user.Email!, otpCode, "password reset");
        }
        catch (OtpCooldownException)
        {
            ModelState.AddModelError(string.Empty, "Please wait before requesting another code.");
            return View(model);
        }
        catch (Exception exception) when (exception is EmailDeliveryException or InvalidOperationException)
        {
            await _otpService.InvalidateExistingOtpsAsync(user.Email!, OtpPurpose.PasswordReset);
            _logger.LogError("Password reset OTP delivery unavailable. Error type: {ErrorType}", exception.GetType().Name);
            ModelState.AddModelError(string.Empty, "Email verification is temporarily unavailable. Please try again later.");
            return View(model);
        }

        TempData["SuccessMessage"] = "If the account exists, a password reset OTP has been sent.";
        return RedirectToAction(nameof(ResetPassword), new { email = user.Email });
    }

    [HttpGet]
    public IActionResult ResetPassword(string? email)
    {
        return View(new ResetPasswordViewModel { Email = email ?? string.Empty });
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    [EnableRateLimiting("otp")]
    public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var user = await _userManager.FindByEmailAsync(model.Email.Trim());
        if (user is null)
        {
            ModelState.AddModelError(string.Empty, "Invalid account.");
            return View(model);
        }

        var validOtp = await _otpService.VerifyOtpAsync(user.Email!, model.OtpCode, OtpPurpose.PasswordReset);
        if (!validOtp)
        {
            ModelState.AddModelError(nameof(ResetPasswordViewModel.OtpCode), "The password reset OTP is invalid or expired.");
            return View(model);
        }

        var resetToken = await _userManager.GeneratePasswordResetTokenAsync(user);
        var result = await _userManager.ResetPasswordAsync(user, resetToken, model.NewPassword);
        if (!result.Succeeded)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }

            return View(model);
        }

        await _userManager.UpdateSecurityStampAsync(user);
        await _otpService.InvalidateExistingOtpsAsync(user.Email!, OtpPurpose.PasswordReset);

        TempData["SuccessMessage"] = "Your password has been reset successfully.";
        return RedirectToAction(nameof(Login));
    }

    [Authorize]
    [HttpGet]
    public async Task<IActionResult> Profile()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user is null)
        {
            return RedirectToAction(nameof(Login));
        }

        var model = new ProfileViewModel
        {
            FullName = user.FullName,
            UserName = user.UserName ?? string.Empty,
            Email = user.Email ?? string.Empty,
            AccountStatus = user.AccountStatus.ToString(),
            IsApproved = user.IsApproved,
            IsActive = user.IsActive,
            CreatedAt = user.CreatedAt,
            LastLoginAt = user.LastLoginAt
        };

        return View(model);
    }

    [Authorize]
    [HttpGet]
    public IActionResult ChangePassword()
    {
        return View(new ChangePasswordViewModel());
    }

    [Authorize]
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ChangePassword(ChangePasswordViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var user = await _userManager.GetUserAsync(User);
        if (user is null)
        {
            return RedirectToAction(nameof(Login));
        }

        var changeResult = await _userManager.ChangePasswordAsync(user, model.CurrentPassword, model.NewPassword);
        if (!changeResult.Succeeded)
        {
            foreach (var error in changeResult.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }

            return View(model);
        }

        await _userManager.UpdateSecurityStampAsync(user);

        TempData["SuccessMessage"] = "Your password was changed successfully.";
        return RedirectToAction(nameof(Profile));
    }

    [HttpGet]
    public IActionResult AccessDenied()
    {
        Response.StatusCode = StatusCodes.Status403Forbidden;
        return View();
    }

    private const string LoginCaptchaSessionKey = "LoginCaptcha";
    private const string RegistrationCaptchaSessionKey = "RegistrationCaptcha";
    private const string CaptchaCharacters = "23456789";
    private static readonly IReadOnlyDictionary<char, string[]> CaptchaGlyphRows = new Dictionary<char, string[]>
    {
        ['2'] = ["01110", "10001", "00001", "00010", "00100", "01000", "11111"],
        ['3'] = ["11110", "00001", "00001", "01110", "00001", "00001", "11110"],
        ['4'] = ["00010", "00110", "01010", "10010", "11111", "00010", "00010"],
        ['5'] = ["11111", "10000", "10000", "11110", "00001", "00001", "11110"],
        ['6'] = ["01111", "10000", "10000", "11110", "10001", "10001", "01110"],
        ['7'] = ["11111", "00001", "00010", "00100", "01000", "01000", "01000"],
        ['8'] = ["01110", "10001", "10001", "01110", "10001", "10001", "01110"],
        ['9'] = ["01110", "10001", "10001", "01111", "00001", "00001", "11110"]
    };

    private void CreateCaptcha(string sessionKey)
    {
        var challenge = new string(Enumerable.Range(0, 6)
            .Select(_ => CaptchaCharacters[RandomNumberGenerator.GetInt32(CaptchaCharacters.Length)])
            .ToArray());

        HttpContext.Session.SetString(sessionKey, challenge);
    }

    private bool ValidateCaptcha(string sessionKey, string? answer)
    {
        var expected = HttpContext.Session.GetString(sessionKey);
        HttpContext.Session.Remove(sessionKey);
        return !string.IsNullOrWhiteSpace(expected)
            && string.Equals(expected, answer?.Trim(), StringComparison.OrdinalIgnoreCase);
    }

    private IActionResult CreateCaptchaImage(string sessionKey)
    {
        var challenge = HttpContext.Session.GetString(sessionKey);
        if (string.IsNullOrWhiteSpace(challenge))
        {
            return NotFound();
        }

        Response.Headers["Cache-Control"] = "no-store, no-cache, must-revalidate";
        Response.Headers["Pragma"] = "no-cache";
        Response.Headers["Expires"] = "0";

        var glyphs = string.Join(string.Empty, challenge.Select((digit, index) =>
        {
            var x = 8 + index * 27;
            var rotation = RandomNumberGenerator.GetInt32(-13, 14);
            var cells = new List<string>();
            for (var row = 0; row < CaptchaGlyphRows[digit].Length; row++)
            {
                for (var column = 0; column < CaptchaGlyphRows[digit][row].Length; column++)
                {
                    if (CaptchaGlyphRows[digit][row][column] != '1')
                    {
                        continue;
                    }

                    var centerX = 1.5 + column * 4 + RandomNumberGenerator.GetInt32(-8, 9) / 10.0;
                    var centerY = 1.5 + row * 4 + RandomNumberGenerator.GetInt32(-8, 9) / 10.0;
                    var radius = RandomNumberGenerator.GetInt32(12, 21) / 10.0;
                    cells.Add(FormattableString.Invariant($"<circle cx=\"{centerX:F1}\" cy=\"{centerY:F1}\" r=\"{radius:F1}\" />"));
                }
            }

            return $"<g transform=\"translate({x} 10) rotate({rotation} 10 14)\">{string.Join(string.Empty, cells)}</g>";
        }));
        var noise = string.Join(string.Empty, Enumerable.Range(0, 9).Select(_ =>
            $"<path d=\"M{RandomNumberGenerator.GetInt32(0, 180)} {RandomNumberGenerator.GetInt32(0, 52)} Q{RandomNumberGenerator.GetInt32(20, 160)} {RandomNumberGenerator.GetInt32(-8, 60)} {RandomNumberGenerator.GetInt32(0, 180)} {RandomNumberGenerator.GetInt32(0, 52)}\" />"));
        var noiseSeed = RandomNumberGenerator.GetInt32(1, int.MaxValue);
        var svg = $"""
            <svg xmlns="http://www.w3.org/2000/svg" width="180" height="52" viewBox="0 0 180 52">
              <defs>
                <filter id="warp" x="-10%" y="-10%" width="120%" height="120%">
                  <feTurbulence type="fractalNoise" baseFrequency="0.04" numOctaves="2" seed="{noiseSeed}" result="noise" />
                  <feDisplacementMap in="SourceGraphic" in2="noise" scale="2.5" xChannelSelector="R" yChannelSelector="G" />
                </filter>
              </defs>
              <rect width="180" height="52" rx="4" fill="#f8f9fa" />
              <g fill="none" stroke="#adb5bd" stroke-width="1">{noise}</g>
              <g fill="#212529" filter="url(#warp)">{glyphs}</g>
            </svg>
            """;
        return Content(svg, "image/svg+xml; charset=utf-8");
    }

    private IActionResult RegistrationFailure(RegisterViewModel model)
    {
        model.CaptchaAnswer = string.Empty;
        var captchaErrors = ModelState.TryGetValue(nameof(model.CaptchaAnswer), out var captchaState)
            ? captchaState.Errors.Select(error => error.ErrorMessage).ToArray()
            : Array.Empty<string>();
        ModelState.Remove(nameof(model.CaptchaAnswer));
        foreach (var error in captchaErrors)
        {
            ModelState.AddModelError(nameof(model.CaptchaAnswer), error);
        }

        CreateCaptcha(RegistrationCaptchaSessionKey);
        return View("Register", model);
    }

    private IActionResult LoginFailure(LoginViewModel model, string loginAs)
    {
        model.LoginAs = loginAs;
        model.UserName = model.UserName?.Trim() ?? string.Empty;
        model.Password = null;
        model.CaptchaAnswer = string.Empty;
        var passwordErrors = ModelState.TryGetValue(nameof(model.Password), out var passwordState)
            ? passwordState.Errors.Select(error => error.ErrorMessage).ToArray()
            : Array.Empty<string>();
        ModelState.Remove(nameof(model.Password));
        foreach (var error in passwordErrors)
        {
            ModelState.AddModelError(nameof(model.Password), error);
        }

        var captchaErrors = ModelState.TryGetValue(nameof(model.CaptchaAnswer), out var captchaState)
            ? captchaState.Errors.Select(error => error.ErrorMessage).ToArray()
            : Array.Empty<string>();
        ModelState.Remove(nameof(model.CaptchaAnswer));
        foreach (var error in captchaErrors)
        {
            ModelState.AddModelError(nameof(model.CaptchaAnswer), error);
        }

        CreateCaptcha(LoginCaptchaSessionKey);
        return View("Login", model);
    }

    private async Task<IActionResult> RedirectToLocal(string? returnUrl, ApplicationUser? user = null)
    {
        if (!string.IsNullOrWhiteSpace(returnUrl) && Url.IsLocalUrl(returnUrl))
        {
            return Redirect(returnUrl);
        }

        if (user is not null && await _userManager.IsInRoleAsync(user, "Admin"))
        {
            return RedirectToAction("Index", "Admin");
        }

        return RedirectToAction("Index", "User");
    }
}
