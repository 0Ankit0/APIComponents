using IdentityAuth.Controllers.User;
using IdentityAuth.Data;
using IdentityAuth.Models.Users;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Moq;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Xunit;

namespace IdentityAuth.Controllers.User.Tests
{
    public class RolesControllerTest
    {
        private readonly RoleManager<Roles> _roleManager;
        private readonly RolesController _controller;
        private readonly DbContextOptions<AppDbContext> _dbContextOptions;
        private readonly AppDbContext _context;

        public RolesControllerTest()
        {
            _dbContextOptions = new DbContextOptionsBuilder<AppDbContext>()
                .UseInMemoryDatabase(databaseName: "InMemoryDb")
                .Options;

            _context = new AppDbContext(_dbContextOptions);
            var roleStore = new RoleStore<Roles>(_context);
            _roleManager = new RoleManager<Roles>(roleStore, null, null, null, null);
            _controller = new RolesController(_roleManager);
        }

        [Fact]
        public void GetRoles_ReturnsOkResult_WithListOfRoles()
        {
            // Arrange
            _context.Roles.AddRange(new Roles("Admin"), new Roles("User"));
            _context.SaveChanges();

            // Act
            var result = _controller.GetRoles();

            // Assert
            var okResult = Assert.IsType<OkObjectResult>(result);
            var returnRoles = Assert.IsType<List<Roles>>(okResult.Value);
            Assert.Equal(2, returnRoles.Count);
        }

        [Fact]
        public async Task GetRoleById_ReturnsOkResult_WithRole()
        {
            // Arrange
            _context.Roles.Add(new Roles("Admin") { Id = "1" });
            _context.SaveChanges();

            // Act
            var result = await _controller.GetRoleById("1");

            // Assert
            var okResult = Assert.IsType<OkObjectResult>(result);
            var returnRole = Assert.IsType<Roles>(okResult.Value);
            Assert.Equal("Admin", returnRole.Name);
        }

        [Fact]
        public async Task GetRoleById_ReturnsNotFound_WhenRoleDoesNotExist()
        {
            // Act
            var result = await _controller.GetRoleById("1");

            // Assert
            Assert.IsType<NotFoundResult>(result);
        }

        [Fact]
        public async Task CreateRole_ReturnsCreatedAtActionResult_WithRole()
        {
            // Arrange
            var model = new RoleModel { Name = "Admin" };

            // Act
            var result = await _controller.CreateRole(model);

            // Assert
            var createdAtActionResult = Assert.IsType<CreatedAtActionResult>(result);
            var returnRole = Assert.IsType<Roles>(createdAtActionResult.Value);
            Assert.Equal("Admin", returnRole.Name);
        }

        [Fact]
        public async Task CreateRole_ReturnsBadRequest_WhenRoleExists()
        {
            // Arrange
            _context.Roles.Add(new Roles("Admin"));
            _context.SaveChanges();
            var model = new RoleModel { Name = "Admin" };

            // Act
            var result = await _controller.CreateRole(model);

            // Assert
            var badRequestResult = Assert.IsType<BadRequestObjectResult>(result);
            Assert.Equal("Role already exists.", ((dynamic)badRequestResult.Value).message);
        }

        [Fact]
        public async Task UpdateRole_ReturnsNoContent_WhenUpdateIsSuccessful()
        {
            // Arrange
            _context.Roles.Add(new Roles("Admin") { Id = "1" });
            _context.SaveChanges();
            var model = new RoleModel { Name = "SuperAdmin" };

            // Act
            var result = await _controller.UpdateRole("1", model);

            // Assert
            Assert.IsType<NoContentResult>(result);
        }

        [Fact]
        public async Task UpdateRole_ReturnsNotFound_WhenRoleDoesNotExist()
        {
            // Arrange
            var model = new RoleModel { Name = "SuperAdmin" };

            // Act
            var result = await _controller.UpdateRole("1", model);

            // Assert
            Assert.IsType<NotFoundResult>(result);
        }

        [Fact]
        public async Task DeleteRole_ReturnsNoContent_WhenDeleteIsSuccessful()
        {
            // Arrange
            _context.Roles.Add(new Roles("Admin") { Id = "1" });
            _context.SaveChanges();

            // Act
            var result = await _controller.DeleteRole("1");

            // Assert
            Assert.IsType<NoContentResult>(result);
        }

        [Fact]
        public async Task DeleteRole_ReturnsNotFound_WhenRoleDoesNotExist()
        {
            // Act
            var result = await _controller.DeleteRole("1");

            // Assert
            Assert.IsType<NotFoundResult>(result);
        }
    }
}