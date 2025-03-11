using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using Moq;
using FluentAssertions;
using IdentityAuth.Controllers.User;
using IdentityAuth.Models.Users;
using IdentityAuth.Data;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Authentication.BearerToken;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using SignInResult = Microsoft.AspNetCore.Identity.SignInResult;
using Xunit;

namespace AuthTest
{
    public class AuthControllerTest
    {
        private Mock<UserManager<Users>> _mockUserManager;
        private Mock<SignInManager<Users>> _mockSignInManager;
        private Mock<IEmailSender<Users>> _mockEmailSender;
        private Mock<LinkGenerator> _mockLinkGenerator;
        private Mock<TimeProvider> _mockTimeProvider;
        private Mock<IOptionsMonitor<BearerTokenOptions>> _mockBearerTokenOptions;
        private AuthController _controller;
        private DbContextOptions<AppDbContext> _dbContextOptions;
        private AppDbContext _context;

        private void InitializeTest(string databaseName)
        {
            _dbContextOptions = new DbContextOptionsBuilder<AppDbContext>()
                .UseInMemoryDatabase(databaseName: databaseName)
                .Options;

            _context = new AppDbContext(_dbContextOptions);

            _mockUserManager = new Mock<UserManager<Users>>(
                Mock.Of<IUserStore<Users>>(), null, null, null, null, null, null, null, null);
            _mockSignInManager = new Mock<SignInManager<Users>>(
                _mockUserManager.Object, Mock.Of<IHttpContextAccessor>(), Mock.Of<IUserClaimsPrincipalFactory<Users>>(), null, null, null, null);
            _mockEmailSender = new Mock<IEmailSender<Users>>();
            _mockLinkGenerator = new Mock<LinkGenerator>();
            _mockTimeProvider = new Mock<TimeProvider>();
            _mockBearerTokenOptions = new Mock<IOptionsMonitor<BearerTokenOptions>>();

            _controller = new AuthController(
                _mockUserManager.Object,
                _mockSignInManager.Object,
                _mockEmailSender.Object,
                _mockLinkGenerator.Object,
                _mockTimeProvider.Object,
                _mockBearerTokenOptions.Object);
        }

        [Fact]
        public async Task Register_InvalidEmail_ReturnsValidationProblem()
        {
            // Arrange
            InitializeTest(nameof(Register_InvalidEmail_ReturnsValidationProblem));
            var registration = new RegisterUserModel { Email = "invalid-email", Password = "Password123!" };

            // Act
            var result = await _controller.Register(registration);

            // Assert
            result.Should().BeOfType<ObjectResult>();
            var objectResult = result as ObjectResult;
            objectResult.StatusCode.Should().Be(StatusCodes.Status400BadRequest);
            var validationProblem = objectResult.Value as ValidationProblemDetails;
            validationProblem.Errors.Keys.Should().Contain("InvalidEmail");
        }

        [Fact]
        public async Task Register_ValidEmail_ReturnsOk()
        {
            // Arrange
            InitializeTest(nameof(Register_ValidEmail_ReturnsOk));
            var registration = new RegisterUserModel { Email = "test@example.com", Password = "Password123!" };
            _mockUserManager.Setup(x => x.CreateAsync(It.IsAny<Users>(), It.IsAny<string>()))
                .ReturnsAsync(IdentityResult.Success);

            // Act
            var result = await _controller.Register(registration);

            // Assert
            result.Should().BeOfType<OkResult>();
        }

        [Fact]
        public async Task Login_InvalidCredentials_ReturnsUnauthorized()
        {
            // Arrange
            InitializeTest(nameof(Login_InvalidCredentials_ReturnsUnauthorized));
            var login = new LoginRequestModel { Email = "test@example.com", Password = "wrongpassword" };
            _mockSignInManager.Setup(x => x.PasswordSignInAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<bool>(), It.IsAny<bool>()))
                .ReturnsAsync(SignInResult.Failed);

            // Act
            var result = await _controller.Login(login, null, null);

            // Assert
            result.Should().BeOfType<ProblemHttpResult>();
            var problemResult = (result as Results<Ok<AccessTokenResponse>, EmptyHttpResult, ProblemHttpResult>).Result as ProblemHttpResult;
            problemResult.StatusCode.Should().Be(StatusCodes.Status401Unauthorized);
        }

        [Fact]
        public async Task Login_ValidCredentials_ReturnsEmpty()
        {
            // Arrange
            InitializeTest(nameof(Login_ValidCredentials_ReturnsEmpty));
            var login = new LoginRequestModel { Email = "test@example.com", Password = "Password123!" };
            _mockSignInManager.Setup(x => x.PasswordSignInAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<bool>(), It.IsAny<bool>()))
                .ReturnsAsync(SignInResult.Success);

            // Act
            var result = await _controller.Login(login, null, null);

            // Assert
            result.Should().BeOfType<EmptyHttpResult>();
        }

        [Fact]
        public async Task Refresh_InvalidToken_ReturnsChallenge()
        {
            // Arrange
            InitializeTest(nameof(Refresh_InvalidToken_ReturnsChallenge));
            var refreshRequest = new RefreshRequestModel { RefreshToken = "invalid-token" };
            _mockBearerTokenOptions.Setup(x => x.Get(It.IsAny<string>()).RefreshTokenProtector.Unprotect(It.IsAny<string>()))
                .Returns((AuthenticationTicket)null);

            // Act
            var result = await _controller.Refresh(refreshRequest);

            // Assert
            result.Should().BeOfType<ChallengeResult>();
        }

        [Fact]
        public async Task Refresh_ValidToken_ReturnsSignIn()
        {
            // Arrange
            InitializeTest(nameof(Refresh_ValidToken_ReturnsSignIn));
            var refreshRequest = new RefreshRequestModel { RefreshToken = "valid-token" };
            var ticket = new AuthenticationTicket(new System.Security.Claims.ClaimsPrincipal(), new AuthenticationProperties(), "Bearer");
            _mockBearerTokenOptions.Setup(x => x.Get(It.IsAny<string>()).RefreshTokenProtector.Unprotect(It.IsAny<string>()))
                .Returns(ticket);
            _mockSignInManager.Setup(x => x.ValidateSecurityStampAsync(It.IsAny<System.Security.Claims.ClaimsPrincipal>()))
                .ReturnsAsync(new Users());

            // Act
            var result = await _controller.Refresh(refreshRequest);

            // Assert
            result.Should().BeOfType<SignInResult>();
        }

        [Fact]
        public async Task ConfirmEmail_InvalidCode_ReturnsUnauthorized()
        {
            // Arrange
            InitializeTest(nameof(ConfirmEmail_InvalidCode_ReturnsUnauthorized));
            var userId = "user-id";
            var code = "invalid-code";
            _mockUserManager.Setup(x => x.FindByIdAsync(userId)).ReturnsAsync(new Users());

            // Act
            var result = await _controller.ConfirmEmail(userId, code);

            // Assert
            result.Should().BeOfType<UnauthorizedResult>();
        }

        [Fact]
        public async Task ConfirmEmail_ValidCode_ReturnsContent()
        {
            // Arrange
            InitializeTest(nameof(ConfirmEmail_ValidCode_ReturnsContent));
            var userId = "user-id";
            var code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes("valid-code"));
            _mockUserManager.Setup(x => x.FindByIdAsync(userId)).ReturnsAsync(new Users());
            _mockUserManager.Setup(x => x.ConfirmEmailAsync(It.IsAny<Users>(), It.IsAny<string>())).ReturnsAsync(IdentityResult.Success);

            // Act
            var result = await _controller.ConfirmEmail(userId, code);

            // Assert
            result.Should().BeOfType<ContentResult>();
        }

        [Fact]
        public async Task ResendConfirmationEmail_UserExists_SendsEmail()
        {
            // Arrange
            InitializeTest(nameof(ResendConfirmationEmail_UserExists_SendsEmail));
            var resendRequest = new ResendConfirmationEmailRequestModel { Email = "test@example.com" };
            _mockUserManager.Setup(x => x.FindByEmailAsync(resendRequest.Email)).ReturnsAsync(new Users());

            // Act
            var result = await _controller.ResendConfirmationEmail(resendRequest);

            // Assert
            result.Should().BeOfType<OkResult>();
            _mockEmailSender.Verify(x => x.SendConfirmationLinkAsync(It.IsAny<Users>(), resendRequest.Email, It.IsAny<string>()), Times.Once);
        }

        [Fact]
        public async Task ForgotPassword_UserExists_SendsEmail()
        {
            // Arrange
            InitializeTest(nameof(ForgotPassword_UserExists_SendsEmail));
            var resetRequest = new ForgotPasswordRequestModel { Email = "test@example.com" };
            _mockUserManager.Setup(x => x.FindByEmailAsync(resetRequest.Email)).ReturnsAsync(new Users());
            _mockUserManager.Setup(x => x.IsEmailConfirmedAsync(It.IsAny<Users>())).ReturnsAsync(true);
            _mockUserManager.Setup(x => x.GeneratePasswordResetTokenAsync(It.IsAny<Users>())).ReturnsAsync("reset-token");

            // Act
            var result = await _controller.ForgotPassword(resetRequest);

            // Assert
            result.Should().BeOfType<OkResult>();
            _mockEmailSender.Verify(x => x.SendPasswordResetCodeAsync(It.IsAny<Users>(), resetRequest.Email, It.IsAny<string>()), Times.Once);
        }

        [Fact]
        public async Task ResetPassword_InvalidToken_ReturnsValidationProblem()
        {
            // Arrange
            InitializeTest(nameof(ResetPassword_InvalidToken_ReturnsValidationProblem));
            var resetRequest = new ResetPasswordRequestModel { Email = "test@example.com", ResetCode = "invalid-code", NewPassword = "NewPassword123!" };
            _mockUserManager.Setup(x => x.FindByEmailAsync(resetRequest.Email)).ReturnsAsync(new Users());
            _mockUserManager.Setup(x => x.IsEmailConfirmedAsync(It.IsAny<Users>())).ReturnsAsync(true);
            _mockUserManager.Setup(x => x.ResetPasswordAsync(It.IsAny<Users>(), It.IsAny<string>(), It.IsAny<string>())).ReturnsAsync(IdentityResult.Failed());

            // Act
            var result = await _controller.ResetPassword(resetRequest);

            // Assert
            result.Should().BeOfType<ObjectResult>();
            var objectResult = result as ObjectResult;
            objectResult.StatusCode.Should().Be(StatusCodes.Status400BadRequest);
        }

        [Fact]
        public async Task ResetPassword_ValidToken_ReturnsOk()
        {
            // Arrange
            InitializeTest(nameof(ResetPassword_ValidToken_ReturnsOk));
            var resetRequest = new ResetPasswordRequestModel { Email = "test@example.com", ResetCode = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes("valid-code")), NewPassword = "NewPassword123!" };
            _mockUserManager.Setup(x => x.FindByEmailAsync(resetRequest.Email)).ReturnsAsync(new Users());
            _mockUserManager.Setup(x => x.IsEmailConfirmedAsync(It.IsAny<Users>())).ReturnsAsync(true);
            _mockUserManager.Setup(x => x.ResetPasswordAsync(It.IsAny<Users>(), It.IsAny<string>(), It.IsAny<string>())).ReturnsAsync(IdentityResult.Success);

            // Act
            var result = await _controller.ResetPassword(resetRequest);

            // Assert
            result.Should().BeOfType<OkResult>();
        }

        [Fact]
        public async Task TwoFactor_EnableWithInvalidCode_ReturnsValidationProblem()
        {
            // Arrange
            InitializeTest(nameof(TwoFactor_EnableWithInvalidCode_ReturnsValidationProblem));
            var tfaRequest = new TwoFactorRequestModel { Enable = true, TwoFactorCode = "invalid-code" };
            _mockUserManager.Setup(x => x.GetUserAsync(It.IsAny<System.Security.Claims.ClaimsPrincipal>())).ReturnsAsync(new Users());
            _mockUserManager.Setup(x => x.VerifyTwoFactorTokenAsync(It.IsAny<Users>(), It.IsAny<string>(), It.IsAny<string>())).ReturnsAsync(false);

            // Act
            var result = await _controller.TwoFactor(tfaRequest);

            // Assert
            result.Should().BeOfType<ObjectResult>();
            var objectResult = result as ObjectResult;
            objectResult.StatusCode.Should().Be(StatusCodes.Status400BadRequest);
        }

        [Fact]
        public async Task TwoFactor_EnableWithValidCode_ReturnsOk()
        {
            // Arrange
            InitializeTest(nameof(TwoFactor_EnableWithValidCode_ReturnsOk));
            var tfaRequest = new TwoFactorRequestModel { Enable = true, TwoFactorCode = "valid-code" };
            _mockUserManager.Setup(x => x.GetUserAsync(It.IsAny<System.Security.Claims.ClaimsPrincipal>())).ReturnsAsync(new Users());
            _mockUserManager.Setup(x => x.VerifyTwoFactorTokenAsync(It.IsAny<Users>(), It.IsAny<string>(), It.IsAny<string>())).ReturnsAsync(true);

            // Act
            var result = await _controller.TwoFactor(tfaRequest);

            // Assert
            result.Should().BeOfType<OkResult>();
        }

        [Fact]
        public async Task GetInfo_UserExists_ReturnsOk()
        {
            // Arrange
            InitializeTest(nameof(GetInfo_UserExists_ReturnsOk));
            _mockUserManager.Setup(x => x.GetUserAsync(It.IsAny<System.Security.Claims.ClaimsPrincipal>())).ReturnsAsync(new Users());
            _mockUserManager.Setup(x => x.GetEmailAsync(It.IsAny<Users>())).ReturnsAsync("test@example.com");
            _mockUserManager.Setup(x => x.IsEmailConfirmedAsync(It.IsAny<Users>())).ReturnsAsync(true);

            // Act
            var result = await _controller.GetInfo();

            // Assert
            result.Should().BeOfType<OkObjectResult>();
            var okResult = result as OkObjectResult;
            var info = okResult.Value as InfoResponseModel;
            info.Email.Should().Be("test@example.com");
            info.IsEmailConfirmed.Should().BeTrue();
        }

        [Fact]
        public async Task UpdateInfo_InvalidEmail_ReturnsValidationProblem()
        {
            // Arrange
            InitializeTest(nameof(UpdateInfo_InvalidEmail_ReturnsValidationProblem));
            var infoRequest = new InfoRequestModel { NewEmail = "invalid-email" };
            _mockUserManager.Setup(x => x.GetUserAsync(It.IsAny<System.Security.Claims.ClaimsPrincipal>())).ReturnsAsync(new Users());

            // Act
            var result = await _controller.UpdateInfo(infoRequest);

            // Assert
            result.Should().BeOfType<ObjectResult>();
            var objectResult = result as ObjectResult;
            objectResult.StatusCode.Should().Be(StatusCodes.Status400BadRequest);
        }

        [Fact]
        public async Task UpdateInfo_ValidEmail_ReturnsOk()
        {
            // Arrange
            InitializeTest(nameof(UpdateInfo_ValidEmail_ReturnsOk));
            var infoRequest = new InfoRequestModel { NewEmail = "test@example.com" };
            _mockUserManager.Setup(x => x.GetUserAsync(It.IsAny<System.Security.Claims.ClaimsPrincipal>())).ReturnsAsync(new Users());
            _mockUserManager.Setup(x => x.GetEmailAsync(It.IsAny<Users>())).ReturnsAsync("old@example.com");

            // Act
            var result = await _controller.UpdateInfo(infoRequest);

            // Assert
            result.Should().BeOfType<OkObjectResult>();
        }
    }
}