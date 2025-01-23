using IndentityManager.Data;
using IndentityManager.Models;
using IndentityManager.Services.IServices;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace IndentityManager.Authorize
{
    public class FirstNameAuthHandler : AuthorizationHandler<FirstNameAuthRequirement>
    {

        public UserManager<ApplicationUser> _userManager { get; set; }
        public ApplicationDbContext _dbContext { get; set; }

        public FirstNameAuthHandler(UserManager<ApplicationUser> userManager, ApplicationDbContext context)
        {
            _userManager = userManager;
            _dbContext = context;
        }

        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, FirstNameAuthRequirement requirement)
        {

            var userId = context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var user = _dbContext.ApplicationUsers.FirstOrDefault(u=>u.Id == userId);
            if (user != null)
            {
                var claims = _userManager.GetClaimsAsync(user).GetAwaiter().GetResult().FirstOrDefault(u => u.Type == "FirstName");

                if (claims != null)
                {
                    if (claims.Value.ToLower().Contains(requirement.Name.ToLower()))
                    {
                        context.Succeed(requirement);
                    }
                }
            }
            return Task.CompletedTask; 
        }
    }
}
