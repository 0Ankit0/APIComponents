using IdentityAuth.Models.Users;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace IdentityAuth.Controllers.Users
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserRoleController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public UserRoleController(UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager)
        {
            _userManager = userManager;
            _roleManager = roleManager;
        }

        // POST: api/UserRole/assign
        [HttpPost("assign")]
        public async Task<IActionResult> AssignRole([FromBody] RoleModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            // Find the user by their ID.
            var user = await _userManager.FindByIdAsync(model?.Id.ToString());
            if (user == null)
                return NotFound(new { Message = "User not found." });

            // Check if the role exists.
            if (!await _roleManager.RoleExistsAsync(model.Name))
                return NotFound(new { Message = "Role not found." });

            // Ensure the user is not already in the role.
            if (await _userManager.IsInRoleAsync(user, model.Name))
                return BadRequest(new { Message = "User is already in the role." });

            var result = await _userManager.AddToRoleAsync(user, model.Name);
            if (result.Succeeded)
                return Ok(new { Message = "Role assigned successfully." });

            return BadRequest(result.Errors);
        }

        // POST: api/UserRole/remove
        [HttpPost("remove")]
        public async Task<IActionResult> RemoveRole([FromBody] RoleModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            // Find the user by their ID.
            var user = await _userManager.FindByIdAsync(model.Id.ToString());
            if (user == null)
                return NotFound(new { Message = "User not found." });

            // Ensure the user is in the role.
            if (!await _userManager.IsInRoleAsync(user, model.Name))
                return BadRequest(new { Message = "User is not in the role." });

            var result = await _userManager.RemoveFromRoleAsync(user, model.Name);
            if (result.Succeeded)
                return Ok(new { Message = "Role removed successfully." });

            return BadRequest(result.Errors);
        }
    }

}
