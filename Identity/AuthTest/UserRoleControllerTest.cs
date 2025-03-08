using IdentityAuth.Controllers.User;
using IdentityAuth.Data;
using IdentityAuth.Models.Users;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.AspNetCore.Mvc;
using Moq;
using System.Threading.Tasks;
using Xunit;

namespace AuthTest
{
    public class UserRoleControllerTest
    {
        private readonly Mock<UserManager<Users>> _mockUserManager;
        private readonly Mock<RoleManager<Roles>> _mockRoleManager;
        private readonly UserRoleController _controller;

        public UserRoleControllerTest()
        {
            var userStoreMock = new Mock<IUserStore<Users>>();
            _mockUserManager = new Mock<UserManager<Users>>(userStoreMock.Object, null, null, null, null, null, null, null, null);

            var roleStoreMock = new Mock<IRoleStore<Roles>>();
            _mockRoleManager = new Mock<RoleManager<Roles>>(roleStoreMock.Object, null, null, null, null);

            _controller = new UserRoleController(_mockUserManager.Object, _mockRoleManager.Object);
        }

        [Fact]
        public async Task AssignRole_UserNotFound_ReturnsNotFound()
        {
            // Arrange
            var model = new UserRoleModel { UserId = "1", RoleName = "Admin" };
            _mockUserManager.Setup(x => x.FindByIdAsync(model.UserId.ToString())).ReturnsAsync((Users)null);

            // Act
            var result = await _controller.AssignRole(model);

            // Assert
            Assert.IsType<NotFoundObjectResult>(result);
        }

        [Fact]
        public async Task AssignRole_RoleNotFound_ReturnsNotFound()
        {
            // Arrange
            var user = new Users();
            var model = new UserRoleModel { UserId = "1", RoleName = "Admin" };
            _mockUserManager.Setup(x => x.FindByIdAsync(model.UserId.ToString())).ReturnsAsync(user);
            _mockRoleManager.Setup(x => x.RoleExistsAsync(model.RoleName)).ReturnsAsync(false);

            // Act
            var result = await _controller.AssignRole(model);

            // Assert
            Assert.IsType<NotFoundObjectResult>(result);
        }

        [Fact]
        public async Task AssignRole_UserAlreadyInRole_ReturnsBadRequest()
        {
            // Arrange
            var user = new Users();
            var model = new UserRoleModel { UserId = "1", RoleName = "Admin" };
            _mockUserManager.Setup(x => x.FindByIdAsync(model.UserId.ToString())).ReturnsAsync(user);
            _mockRoleManager.Setup(x => x.RoleExistsAsync(model.RoleName)).ReturnsAsync(true);
            _mockUserManager.Setup(x => x.IsInRoleAsync(user, model.RoleName)).ReturnsAsync(true);

            // Act
            var result = await _controller.AssignRole(model);

            // Assert
            Assert.IsType<BadRequestObjectResult>(result);
        }

        [Fact]
        public async Task AssignRole_Success_ReturnsOk()
        {
            // Arrange
            var user = new Users();
            var model = new UserRoleModel { UserId = "1", RoleName = "Admin" };
            _mockUserManager.Setup(x => x.FindByIdAsync(model.UserId.ToString())).ReturnsAsync(user);
            _mockRoleManager.Setup(x => x.RoleExistsAsync(model.RoleName)).ReturnsAsync(true);
            _mockUserManager.Setup(x => x.IsInRoleAsync(user, model.RoleName)).ReturnsAsync(false);
            _mockUserManager.Setup(x => x.AddToRoleAsync(user, model.RoleName)).ReturnsAsync(IdentityResult.Success);

            // Act
            var result = await _controller.AssignRole(model);

            // Assert
            Assert.IsType<OkObjectResult>(result);
        }

        [Fact]
        public async Task RemoveRole_UserNotFound_ReturnsNotFound()
        {
            // Arrange
            var model = new UserRoleModel { UserId = "1", RoleName = "Admin" };
            _mockUserManager.Setup(x => x.FindByIdAsync(model.UserId.ToString())).ReturnsAsync((Users)null);

            // Act
            var result = await _controller.RemoveRole(model);

            // Assert
            Assert.IsType<NotFoundObjectResult>(result);
        }

        [Fact]
        public async Task RemoveRole_UserNotInRole_ReturnsBadRequest()
        {
            // Arrange
            var user = new Users();
            var model = new UserRoleModel { UserId = "1", RoleName = "Admin" };
            _mockUserManager.Setup(x => x.FindByIdAsync(model.UserId.ToString())).ReturnsAsync(user);
            _mockUserManager.Setup(x => x.IsInRoleAsync(user, model.RoleName)).ReturnsAsync(false);

            // Act
            var result = await _controller.RemoveRole(model);

            // Assert
            Assert.IsType<BadRequestObjectResult>(result);
        }

        [Fact]
        public async Task RemoveRole_Success_ReturnsOk()
        {
            // Arrange
            var user = new Users();
            var model = new UserRoleModel { UserId = "1", RoleName = "Admin" };
            _mockUserManager.Setup(x => x.FindByIdAsync(model.UserId.ToString())).ReturnsAsync(user);
            _mockUserManager.Setup(x => x.IsInRoleAsync(user, model.RoleName)).ReturnsAsync(true);
            _mockUserManager.Setup(x => x.RemoveFromRoleAsync(user, model.RoleName)).ReturnsAsync(IdentityResult.Success);

            // Act
            var result = await _controller.RemoveRole(model);

            // Assert
            Assert.IsType<OkObjectResult>(result);
        }
    }
}