using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using IdentityAuth.Models.Users;
using Microsoft.AspNetCore.Authentication.BearerToken;
using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Http.HttpResults;
using IdentityAuth.Data;
using Microsoft.AspNetCore.Authentication;
using IdentityAuth.Filters;

namespace IdentityAuth.Controllers.User
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<Users> _userManager;
        private readonly SignInManager<Users> _signInManager;
        private readonly IEmailSender<Users> _emailSender;
        private readonly LinkGenerator _linkGenerator;
        private readonly TimeProvider _timeProvider;
        private readonly IOptionsMonitor<BearerTokenOptions> _bearerTokenOptions;
        // private readonly IValidator<RegisterRequest> _registerValidator;
        private static readonly EmailAddressAttribute _emailAddressAttribute = new();

        public AuthController(
            UserManager<Users> userManager,
            SignInManager<Users> signInManager,
            IEmailSender<Users> emailSender,
            LinkGenerator linkGenerator,
            TimeProvider timeProvider,
            IOptionsMonitor<BearerTokenOptions> bearerTokenOptions
            )
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _emailSender = emailSender;
            _linkGenerator = linkGenerator;
            _timeProvider = timeProvider;
            _bearerTokenOptions = bearerTokenOptions;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterUserModel registration)
        {

            if (!_emailAddressAttribute.IsValid(registration.Email))
            {
                var error = _userManager.ErrorDescriber.InvalidEmail(registration.Email);
                return CreateValidationProblem(error.Code, error.Description);
            }

            Users user = new Users { UserName = registration.Email, Email = registration.Email };
            IdentityResult result = await _userManager.CreateAsync(user, registration.Password);
            if (!result.Succeeded)
            {
                return CreateValidationProblem(result);
            }

            await SendConfirmationEmailAsync(user, registration.Email);
            return Ok();
        }

        // To enable password failures to trigger account lockout, set lockoutOnFailure: true
        [HttpPost("login")]
        public async Task<Results<Ok<AccessTokenResponse>, EmptyHttpResult, ProblemHttpResult>> Login(
            [FromBody] LoginRequestModel login,
            [FromQuery] bool? useCookies,
            [FromQuery] bool? useSessionCookies)
        {
            bool useCookieScheme = (useCookies == true) || (useSessionCookies == true);
            bool isPersistent = (useCookies == true) && (useSessionCookies != true);
            _signInManager.AuthenticationScheme = useCookieScheme
                ? IdentityConstants.ApplicationScheme
                : IdentityConstants.BearerScheme;

            var result = await _signInManager.PasswordSignInAsync(login.Email, login.Password, isPersistent, lockoutOnFailure: true);

            if (result.RequiresTwoFactor)
            {
                if (!string.IsNullOrEmpty(login.TwoFactorCode))
                {
                    result = await _signInManager.TwoFactorAuthenticatorSignInAsync(login.TwoFactorCode, isPersistent, rememberClient: isPersistent);
                }
                else if (!string.IsNullOrEmpty(login.TwoFactorRecoveryCode))
                {
                    result = await _signInManager.TwoFactorRecoveryCodeSignInAsync(login.TwoFactorRecoveryCode);
                }
            }

            if (!result.Succeeded)
            {
                return TypedResults.Problem(result.ToString(), statusCode: StatusCodes.Status401Unauthorized);
            }

            return TypedResults.Empty;
        }

        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh([FromBody] RefreshRequestModel refreshRequest)
        {
            var refreshTokenProtector = _bearerTokenOptions.Get(IdentityConstants.BearerScheme).RefreshTokenProtector;
            var refreshTicket = refreshTokenProtector.Unprotect(refreshRequest.RefreshToken);

            if (refreshTicket?.Properties?.ExpiresUtc is not { } expiresUtc ||
                _timeProvider.GetUtcNow() >= expiresUtc ||
                await _signInManager.ValidateSecurityStampAsync(refreshTicket.Principal) is not Users user)
            {
                return Challenge();
            }

            var newPrincipal = await _signInManager.CreateUserPrincipalAsync(user);
            return SignIn(newPrincipal, authenticationScheme: IdentityConstants.BearerScheme);
        }

        [HttpGet("confirmEmail")]
        public async Task<IActionResult> ConfirmEmail(
            [FromQuery] string userId,
            [FromQuery] string code,
            [FromQuery] string changedEmail = "")
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return Unauthorized();
            }

            try
            {
                code = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(code));
            }
            catch (FormatException)
            {
                return Unauthorized();
            }

            IdentityResult result;
            if (string.IsNullOrEmpty(changedEmail))
            {
                result = await _userManager.ConfirmEmailAsync(user, code);
            }
            else
            {
                result = await _userManager.ChangeEmailAsync(user, changedEmail, code);
                if (result.Succeeded)
                {
                    result = await _userManager.SetUserNameAsync(user, changedEmail);
                }
            }

            if (!result.Succeeded)
            {
                return Unauthorized();
            }

            return Content("Thank you for confirming your email.");
        }

        [HttpPost("resendConfirmationEmail")]
        public async Task<IActionResult> ResendConfirmationEmail([FromBody] ResendConfirmationEmailRequestModel resendRequest)
        {
            var user = await _userManager.FindByEmailAsync(resendRequest.Email);
            if (user != null)
            {
                await SendConfirmationEmailAsync(user, resendRequest.Email);
            }
            return Ok();
        }

        [HttpPost("forgotPassword")]
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordRequestModel resetRequest)
        {
            var user = await _userManager.FindByEmailAsync(resetRequest.Email);
            if (user != null && await _userManager.IsEmailConfirmedAsync(user))
            {
                string code = await _userManager.GeneratePasswordResetTokenAsync(user);
                code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));
                await _emailSender.SendPasswordResetCodeAsync(user, resetRequest.Email, HtmlEncoder.Default.Encode(code));
            }
            return Ok();
        }

        [HttpPost("resetPassword")]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequestModel resetRequest)
        {
            var user = await _userManager.FindByEmailAsync(resetRequest.Email);
            if (user == null || !await _userManager.IsEmailConfirmedAsync(user))
            {
                var error = _userManager.ErrorDescriber.InvalidToken();
                return CreateValidationProblem(error.Code, error.Description);
            }

            IdentityResult result;
            try
            {
                string code = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(resetRequest.ResetCode));
                result = await _userManager.ResetPasswordAsync(user, code, resetRequest.NewPassword);
            }
            catch (FormatException)
            {
                var error = _userManager.ErrorDescriber.InvalidToken();
                result = IdentityResult.Failed(error);
            }

            if (!result.Succeeded)
            {
                return CreateValidationProblem(result);
            }

            return Ok();
        }

        // -------------------- Manage Endpoints --------------------

        [HttpPost("manage/2fa")]
        [Authorize]
        public async Task<IActionResult> TwoFactor([FromBody] TwoFactorRequestModel tfaRequest)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound();
            }

            if (tfaRequest.Enable)
            {
                if (tfaRequest.ResetSharedKey)
                {
                    return CreateValidationProblem("CannotResetSharedKeyAndEnable",
                        "Resetting the 2fa shared key must disable 2fa until a 2fa token based on the new shared key is validated.");
                }
                else if (string.IsNullOrEmpty(tfaRequest.TwoFactorCode))
                {
                    return CreateValidationProblem("RequiresTwoFactor",
                        "No 2fa token was provided by the request. A valid 2fa token is required to enable 2fa.");
                }
                else if (!await _userManager.VerifyTwoFactorTokenAsync(user, _userManager.Options.Tokens.AuthenticatorTokenProvider, tfaRequest.TwoFactorCode))
                {
                    return CreateValidationProblem("InvalidTwoFactorCode",
                        "The 2fa token provided by the request was invalid. A valid 2fa token is required to enable 2fa.");
                }

                await _userManager.SetTwoFactorEnabledAsync(user, true);
            }
            else if (!tfaRequest.Enable || tfaRequest.ResetSharedKey)
            {
                await _userManager.SetTwoFactorEnabledAsync(user, false);
            }

            if (tfaRequest.ResetSharedKey)
            {
                await _userManager.ResetAuthenticatorKeyAsync(user);
            }

            string[] recoveryCodes = null;
            if (tfaRequest.ResetRecoveryCodes || (tfaRequest.Enable && await _userManager.CountRecoveryCodesAsync(user) == 0))
            {
                recoveryCodes = (await _userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10)).ToArray();
            }

            if (tfaRequest.ForgetMachine)
            {
                await _signInManager.ForgetTwoFactorClientAsync();
            }

            string key = await _userManager.GetAuthenticatorKeyAsync(user);
            if (string.IsNullOrEmpty(key))
            {
                await _userManager.ResetAuthenticatorKeyAsync(user);
                key = await _userManager.GetAuthenticatorKeyAsync(user);
                if (string.IsNullOrEmpty(key))
                {
                    throw new NotSupportedException("The user manager must produce an authenticator key after reset.");
                }
            }

            var response = new TwoFactorResponseModel
            {
                SharedKey = key,
                RecoveryCodes = recoveryCodes,
                RecoveryCodesLeft = recoveryCodes?.Length ?? await _userManager.CountRecoveryCodesAsync(user),
                IsTwoFactorEnabled = await _userManager.GetTwoFactorEnabledAsync(user),
                IsMachineRemembered = await _signInManager.IsTwoFactorClientRememberedAsync(user),
            };

            return Ok(response);
        }

        [HttpGet("manage/info")]
        [TokenAuth]
        public async Task<IActionResult> GetInfo()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound();
            }

            var info = new InfoResponseModel
            {
                Email = await _userManager.GetEmailAsync(user),
                IsEmailConfirmed = await _userManager.IsEmailConfirmedAsync(user)
            };

            return Ok(info);
        }

        [HttpPost("manage/info")]
        public async Task<IActionResult> UpdateInfo([FromBody] InfoRequestModel infoRequest)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound();
            }

            if (!string.IsNullOrEmpty(infoRequest.NewEmail) && !_emailAddressAttribute.IsValid(infoRequest.NewEmail))
            {
                var error = _userManager.ErrorDescriber.InvalidEmail(infoRequest.NewEmail);
                return CreateValidationProblem(error.Code, error.Description);
            }

            if (!string.IsNullOrEmpty(infoRequest.NewPassword))
            {
                if (string.IsNullOrEmpty(infoRequest.OldPassword))
                {
                    return CreateValidationProblem("OldPasswordRequired",
                        "The old password is required to set a new password. If the old password is forgotten, use /resetPassword.");
                }
                var changePasswordResult = await _userManager.ChangePasswordAsync(user, infoRequest.OldPassword, infoRequest.NewPassword);
                if (!changePasswordResult.Succeeded)
                {
                    return CreateValidationProblem(changePasswordResult);
                }
            }

            if (!string.IsNullOrEmpty(infoRequest.NewEmail))
            {
                string email = await _userManager.GetEmailAsync(user);
                if (email != infoRequest.NewEmail)
                {
                    await SendConfirmationEmailAsync(user, infoRequest.NewEmail, isChange: true);
                }
            }

            var info = new InfoResponseModel
            {
                Email = await _userManager.GetEmailAsync(user),
                IsEmailConfirmed = await _userManager.IsEmailConfirmedAsync(user)
            };
            return Ok(info);
        }

        // -------------------- Private Helpers --------------------

        private async Task SendConfirmationEmailAsync(Users user, string email, bool isChange = false)
        {
            string code = isChange
                ? await _userManager.GenerateChangeEmailTokenAsync(user, email)
                : await _userManager.GenerateEmailConfirmationTokenAsync(user);
            code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));

            string userId = await _userManager.GetUserIdAsync(user);
            var routeValues = new RouteValueDictionary
            {
                ["userId"] = userId,
                ["code"] = code
            };

            if (isChange)
            {
                routeValues.Add("changedEmail", email);
            }

            string confirmEmailUrl = _linkGenerator.GetUriByAction(HttpContext, action: "ConfirmEmail", controller: "Auth", values: routeValues)
                ?? throw new NotSupportedException("Could not generate confirmation email URL.");

            await _emailSender.SendConfirmationLinkAsync(user, email, HtmlEncoder.Default.Encode(confirmEmailUrl));
        }

        private IActionResult CreateValidationProblem(string errorCode, string errorDescription)
        {
            var errors = new Dictionary<string, string[]>
            {
                { errorCode, new[] { errorDescription } }
            };

            var problemDetails = new ValidationProblemDetails(errors);
            return ValidationProblem(problemDetails);
        }


        private IActionResult CreateValidationProblem(IdentityResult result)
        {
            var errors = result.Errors.ToDictionary(e => e.Code, e => new[] { e.Description });
            var problemDetails = new ValidationProblemDetails(errors);
            return ValidationProblem(problemDetails);
        }
    }
}
