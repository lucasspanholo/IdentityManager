using IndentityManager.Data;
using IndentityManager.Models;
using IndentityManager.Models.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace IndentityManager.Controllers
{
    public class UserController : Controller
    {
        private readonly ApplicationDbContext _db;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;


        public UserController(ApplicationDbContext db, UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager)
        {
            _db = db;
            _userManager = userManager;
            _roleManager = roleManager;
        }

        [HttpGet]
        public async Task<IActionResult> Index()
        {
            var userList = _db.ApplicationUsers.ToList();

            foreach (var user in userList)
            {
                var user_role = await _userManager.GetRolesAsync(user) as List<string>;
                user.Role = String.Join(",", user_role);

                var user_claim = _userManager.GetClaimsAsync(user).GetAwaiter().GetResult().Select(u => u.Type);
                user.UserClaim = String.Join(",", user_claim);
            }

            return View(userList);
        }


        ///ROLES
        [HttpGet]
        public async Task<IActionResult> ManageRole(string userId)
        {
            ApplicationUser user = await _userManager.FindByIdAsync(userId);

            if (user == null)
            {
                return NotFound();
            }

            List<string> existingUserRoles = await _userManager.GetRolesAsync(user) as List<string>;

            var model = new RolesViewModel()
            {
                User = user
            };

            foreach (var role in _roleManager.Roles)
            {
                RoleSelection roleSelection = new()
                {
                    RoleName = role.Name
                };
                if (existingUserRoles.Any(c => c == role.Name))
                {
                    roleSelection.IsSelected = true;
                }
                model.RolesList.Add(roleSelection);
            }
            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ManageRole(RolesViewModel rolesViewModel)
        {
            ApplicationUser user = await _userManager.FindByIdAsync(rolesViewModel.User.Id);

            if (user == null)
            {
                return View();
            }

            var oldUserRoles = await _userManager.GetRolesAsync(user);
            var result = await _userManager.RemoveFromRolesAsync(user, oldUserRoles);

            if (!result.Succeeded) 
            {
                TempData[SD.Error] = "Error removing roles";
                return View(rolesViewModel);
            }

            result = await _userManager.AddToRolesAsync(user, 
                rolesViewModel.RolesList.Where(x => x.IsSelected).Select(y => y.RoleName));

            if (!result.Succeeded)
            {
                TempData[SD.Error] = "Error adding roles";
                return View(rolesViewModel);
            }

            TempData[SD.Sucess] = "Roles assigned successfully";
            return RedirectToAction(nameof(Index));

        }


        ///CLAIMS

        [HttpGet]
        public async Task<IActionResult> ManageUserClaim(string userId)
        {
            ApplicationUser user = await _userManager.FindByIdAsync(userId);

            if (user == null)
            {
                return View();
            }

            var existingUserClaims = await _userManager.GetClaimsAsync(user);

            var model = new ClaimsViewModel()
            {
                User = user
            };

            foreach (Claim claim in ClaimStore.claimsList)
            {
                ClaimSelection userClaim = new()
                {
                    ClaimType = claim.Type
                };
                if (existingUserClaims.Any(c => c.Type == claim.Type))
                {
                    userClaim.IsSelected = true;
                }
                model.ClaimList.Add(userClaim);
            }
            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ManageUserClaim(ClaimsViewModel claimsViewModel)
        {
            ApplicationUser user = await _userManager.FindByIdAsync(claimsViewModel.User.Id);

            if (user == null)
            {
                return NotFound();
            }

            var oldClaims = await _userManager.GetClaimsAsync(user);
            var result = await _userManager.RemoveClaimsAsync(user, oldClaims);

            if (!result.Succeeded)
            {
                TempData[SD.Error] = "Error removing roles";
                return View(claimsViewModel);
            }

            result = await _userManager.AddClaimsAsync(user,
                claimsViewModel.ClaimList.Where(x => x.IsSelected).Select(y => new Claim(y.ClaimType, y.IsSelected.ToString())));

            if (!result.Succeeded)
            {
                TempData[SD.Error] = "Error adding claims";
                return View(claimsViewModel);
            }

            TempData[SD.Sucess] = "Claims assigned successfully";
            return RedirectToAction(nameof(Index));

        }
    }
}
