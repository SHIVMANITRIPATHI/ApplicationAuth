using System.Net.Mail;
using System.Security.Claims;
using System.Text.Json;
using ApplicationAuth.Data;
using ApplicationAuth.Models;
using ApplicationAuth.Services;
using ApplicationAuth.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;

namespace ApplicationAuth.Controllers;

public class AccountController : Controller
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly ApplicationDbContext _context;
    private readonly IOtpService _otpService;
    private readonly IEmailService _emailService;
    private readonly ILogger<AccountController> _logger;

    public AccountController(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        RoleManager<IdentityRole> roleManager,
        ApplicationDbContext context,
        IOtpService otpService,
        IEmailService emailService,
        ILogger<AccountController> logger)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _roleManager = roleManager;
        _context = context;
        _otpService = otpService;
        _emailService = emailService;
        _logger = logger;
    }

    [HttpGet]
    public IActionResult Register()
    {
        return View(new RegisterViewModel());
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    [EnableRateLimiting("otp")]
    public async Task<IActionResult> Register(RegisterViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var normalizedEmail = model.Email.Trim();
        var normalizedUserName = model.UserName.Trim();

        if (await _userManager.FindByEmailAsync(normalizedEmail) is not null)
        {
            ModelState.AddModelError(nameof(RegisterViewModel.Email), "An account with this email already exists.");
            return View(model);
        }

        if (await _userManager.FindByNameAsync(normalizedUserName) is not null)
        {
            ModelState.AddModelError(nameof(RegisterViewModel.UserName), "This username is already taken.");
            return View(model);
        }

        var validOtp = await _otpService.VerifyOtpAsync(normalizedEmail, model.OtpCode, OtpPurpose.Registration);
        if (!validOtp)
        {
            ModelState.AddModelError(nameof(RegisterViewModel.OtpCode), "The registration OTP is invalid or expired.");
            return View(model);
        }

        var user = new ApplicationUser
        {
            UserName = normalizedUserName,
            Email = normalizedEmail,
            FullName = model.FullName.Trim(),
            IsApproved = false,
            IsActive = false,
            AccountStatus = UserAccountStatus.Pending,
            CreatedAt = DateTime.UtcNow,
            EmailConfirmed = true
        };

        var result = await _userManager.CreateAsync(user, model.Password);
        if (!result.Succeeded)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }

            return View(model);
        }

        await _userManager.AddToRoleAsync(user, "User");

        TempData["SuccessMessage"] = "Your registration has been submitted and is awaiting administrator approval.";
        return RedirectToAction(nameof(RegistrationSubmitted));
    }

    [HttpGet]
    public IActionResult RegistrationSubmitted()
    {
        return View();
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    [EnableRateLimiting("otp")]
    public async Task<IActionResult> SendRegistrationOtp(string email)
    {
        var normalizedEmail = email?.Trim();
        if (string.IsNullOrWhiteSpace(normalizedEmail) || !MailAddress.TryCreate(normalizedEmail, out _))
        {
            return Json(new { success = false, message = "Enter a valid email address." });
        }

        if (await _userManager.FindByEmailAsync(normalizedEmail) is not null)
        {
            return Json(new { success = false, message = "An account with this email already exists." });
        }

        try
        {
            var otpCode = await _otpService.GenerateOtpAsync(normalizedEmail, OtpPurpose.Registration);
            await _emailService.SendOtpAsync(normalizedEmail, otpCode, "registration");
            return Json(new { success = true, message = "If eligible, a verification code has been sent to that email." });
        }
        catch (OtpCooldownException)
        {
            return StatusCode(StatusCodes.Status429TooManyRequests,
                new { success = false, message = "Please wait before requesting another code." });
        }
        catch (Exception exception) when (exception is EmailDeliveryException or InvalidOperationException)
        {
            await _otpService.InvalidateExistingOtpsAsync(normalizedEmail, OtpPurpose.Registration);
            _logger.LogError("Registration OTP delivery unavailable. Error type: {ErrorType}", exception.GetType().Name);
            return StatusCode(StatusCodes.Status503ServiceUnavailable,
                new { success = false, message = "Email verification is temporarily unavailable." });
        }
    }

    [HttpGet]
    public IActionResult Login(string? returnUrl = null)
    {
        ViewData["ReturnUrl"] = returnUrl;
        return View(new LoginViewModel { LoginAs = "User" });
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> AdminLogin(string? userNameOrEmail, string? password, bool rememberMe)
    {
        var identifier = userNameOrEmail?.Trim();
        if (string.IsNullOrWhiteSpace(identifier) || string.IsNullOrWhiteSpace(password))
        {
            return AdminLoginFailure(identifier, rememberMe);
        }

        var user = await _userManager.FindByNameAsync(identifier)
                   ?? await _userManager.FindByEmailAsync(identifier);
        if (user is null
            || !await _userManager.IsInRoleAsync(user, "Admin")
            || !user.IsApproved
            || !user.IsActive
            || user.AccountStatus != UserAccountStatus.Approved)
        {
            return AdminLoginFailure(identifier, rememberMe);
        }

        var result = await _signInManager.PasswordSignInAsync(user, password, rememberMe, lockoutOnFailure: true);
        if (result.Succeeded)
        {
            user.LastLoginAt = DateTime.UtcNow;
            user.UpdatedAt = DateTime.UtcNow;
            var updateResult = await _userManager.UpdateAsync(user);
            if (!updateResult.Succeeded)
            {
                await _signInManager.SignOutAsync();
                return AdminLoginFailure(identifier, rememberMe);
            }

            return await RedirectToLocal(null, user);
        }

        return AdminLoginFailure(identifier, rememberMe);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    [Authorize]
    public async Task<IActionResult> Logout()
    {
        await _signInManager.SignOutAsync();
        return RedirectToAction(nameof(Login));
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    [EnableRateLimiting("otp")]
    public async Task<IActionResult> SendLoginOtp(string email, string password, bool rememberMe)
    {
        var normalizedEmail = email?.Trim();
        var normalizedPassword = password ?? string.Empty;

        if (string.IsNullOrWhiteSpace(normalizedEmail) || !MailAddress.TryCreate(normalizedEmail, out _) || string.IsNullOrWhiteSpace(normalizedPassword))
        {
            ModelState.AddModelError(string.Empty, "Invalid email or password.");
            return View("Login", new LoginViewModel { Email = normalizedEmail ?? string.Empty, Password = string.Empty, LoginAs = "User" });
        }

        var account = await _userManager.FindByEmailAsync(normalizedEmail);
        if (account is null)
        {
            ModelState.AddModelError(string.Empty, "Invalid email or password.");
            return View("Login", new LoginViewModel { Email = normalizedEmail, Password = string.Empty, LoginAs = "User" });
        }

        if (await _userManager.IsInRoleAsync(account, "Admin") || !await _userManager.IsInRoleAsync(account, "User"))
        {
            ModelState.AddModelError(string.Empty, "Invalid email or password.");
            return View("Login", new LoginViewModel { Email = normalizedEmail, Password = string.Empty, LoginAs = "User" });
        }

        if (account.AccountStatus == UserAccountStatus.Pending)
        {
            ModelState.AddModelError(string.Empty, "Your account is pending administrator approval.");
            return View("Login", new LoginViewModel { Email = normalizedEmail, Password = string.Empty, LoginAs = "User" });
        }

        if (account.AccountStatus == UserAccountStatus.Rejected)
        {
            ModelState.AddModelError(string.Empty, "Your account has been rejected. Please contact the administrator.");
            return View("Login", new LoginViewModel { Email = normalizedEmail, Password = string.Empty, LoginAs = "User" });
        }

        if (!account.IsActive || account.AccountStatus == UserAccountStatus.Suspended)
        {
            ModelState.AddModelError(string.Empty, "Your account is currently inactive. Please contact the administrator.");
            return View("Login", new LoginViewModel { Email = normalizedEmail, Password = string.Empty, LoginAs = "User" });
        }

        if (!account.IsApproved || account.AccountStatus != UserAccountStatus.Approved)
        {
            ModelState.AddModelError(string.Empty, "Your account is pending administrator approval.");
            return View("Login", new LoginViewModel { Email = normalizedEmail, Password = string.Empty, LoginAs = "User" });
        }

        var passwordIsValid = await _userManager.CheckPasswordAsync(account, normalizedPassword);
        if (!passwordIsValid)
        {
            ModelState.AddModelError(string.Empty, "Invalid email or password.");
            return View("Login", new LoginViewModel { Email = normalizedEmail, Password = string.Empty, LoginAs = "User" });
        }

        try
        {
            var otpCode = await _otpService.GenerateOtpAsync(account.Email!, OtpPurpose.Login, account.Id);
            await _emailService.SendOtpAsync(account.Email!, otpCode, "login");
            await StorePendingUserLoginChallengeAsync(account.Email!, rememberMe);
            return View("Login", new LoginViewModel
            {
                Email = normalizedEmail,
                Password = string.Empty,
                LoginAs = "User",
                RememberMe = rememberMe,
                ShowOtpSection = true
            });
        }
        catch (OtpCooldownException)
        {
            ModelState.AddModelError(string.Empty, "Please wait before requesting another code.");
            return View("Login", new LoginViewModel { Email = normalizedEmail, Password = string.Empty, LoginAs = "User" });
        }
        catch (Exception exception) when (exception is EmailDeliveryException or InvalidOperationException)
        {
            await _otpService.InvalidateExistingOtpsAsync(account.Email!, OtpPurpose.Login);
            _logger.LogError("Login OTP delivery unavailable. Error type: {ErrorType}", exception.GetType().Name);
            ModelState.AddModelError(string.Empty, "Email verification is temporarily unavailable. Please try again later.");
            return View("Login", new LoginViewModel { Email = normalizedEmail, Password = string.Empty, LoginAs = "User" });
        }
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    [EnableRateLimiting("otp")]
    public async Task<IActionResult> VerifyLoginOtp(string email, string otpCode, bool rememberMe)
    {
        var normalizedEmail = email?.Trim();
        if (string.IsNullOrWhiteSpace(normalizedEmail) || !MailAddress.TryCreate(normalizedEmail, out _)
            || string.IsNullOrWhiteSpace(otpCode) || otpCode.Length != 6 || !otpCode.All(char.IsDigit))
        {
            ModelState.AddModelError(string.Empty, "Enter a valid email address and six-digit code.");
            return View("Login", new LoginViewModel { Email = normalizedEmail ?? string.Empty, OtpCode = otpCode, LoginAs = "User", ShowOtpSection = true });
        }

        var challenge = await GetPendingUserLoginChallengeAsync();
        if (challenge is null || !string.Equals(challenge.Email, normalizedEmail, StringComparison.OrdinalIgnoreCase) || challenge.ExpiresAtUtc <= DateTime.UtcNow)
        {
            HttpContext.Session.Remove(PendingUserLoginSessionKey);
            ModelState.AddModelError(string.Empty, "The verification code is invalid or expired.");
            return View("Login", new LoginViewModel { Email = normalizedEmail, OtpCode = otpCode, LoginAs = "User", ShowOtpSection = true });
        }

        var account = await _userManager.FindByEmailAsync(normalizedEmail);
        if (account is null || !account.IsApproved || !account.IsActive
            || account.AccountStatus != UserAccountStatus.Approved
            || await _userManager.IsInRoleAsync(account, "Admin")
            || !await _userManager.IsInRoleAsync(account, "User"))
        {
            HttpContext.Session.Remove(PendingUserLoginSessionKey);
            ModelState.AddModelError(string.Empty, "This account is not eligible for sign-in.");
            return View("Login", new LoginViewModel { Email = normalizedEmail, OtpCode = otpCode, LoginAs = "User", ShowOtpSection = true });
        }

        if (!await _otpService.VerifyOtpAsync(account.Email!, otpCode, OtpPurpose.Login))
        {
            ModelState.AddModelError(string.Empty, "The verification code is invalid or expired.");
            return View("Login", new LoginViewModel { Email = normalizedEmail, OtpCode = otpCode, LoginAs = "User", ShowOtpSection = true });
        }

        HttpContext.Session.Remove(PendingUserLoginSessionKey);

        account.LastLoginAt = DateTime.UtcNow;
        account.UpdatedAt = DateTime.UtcNow;
        var updateResult = await _userManager.UpdateAsync(account);
        if (!updateResult.Succeeded)
        {
            ModelState.AddModelError(string.Empty, "Sign-in could not be completed. Please try again.");
            return View("Login", new LoginViewModel { Email = normalizedEmail, OtpCode = otpCode, LoginAs = "User", ShowOtpSection = true });
        }

        await _signInManager.SignInAsync(account, challenge.RememberMe || rememberMe);
        return await RedirectToLocal(null, account);
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

    private const string PendingUserLoginSessionKey = "PendingUserLoginChallenge";

    private async Task StorePendingUserLoginChallengeAsync(string email, bool rememberMe)
    {
        var challenge = new PendingUserLoginChallenge
        {
            Email = email,
            RememberMe = rememberMe,
            ExpiresAtUtc = DateTime.UtcNow.AddMinutes(10)
        };

        HttpContext.Session.SetString(PendingUserLoginSessionKey, JsonSerializer.Serialize(challenge));
    }

    private async Task<PendingUserLoginChallenge?> GetPendingUserLoginChallengeAsync()
    {
        var value = HttpContext.Session.GetString(PendingUserLoginSessionKey);
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        try
        {
            var challenge = JsonSerializer.Deserialize<PendingUserLoginChallenge>(value);
            return challenge is null || string.IsNullOrWhiteSpace(challenge.Email) ? null : challenge;
        }
        catch (JsonException)
        {
            HttpContext.Session.Remove(PendingUserLoginSessionKey);
            return null;
        }
    }

    private sealed class PendingUserLoginChallenge
    {
        public string Email { get; set; } = string.Empty;
        public bool RememberMe { get; set; }
        public DateTime ExpiresAtUtc { get; set; }
    }

    private IActionResult AdminLoginFailure(string? identifier, bool rememberMe)
    {
        ModelState.Clear();
        ModelState.AddModelError(string.Empty, "Invalid email or password.");
        return View("Login", new LoginViewModel
        {
            LoginAs = "Admin",
            UserNameOrEmail = identifier ?? string.Empty,
            RememberMe = rememberMe
        });
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
