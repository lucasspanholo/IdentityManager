using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IndentityManager.Controllers
{
    [Authorize]
    public class AccessCheckerController : Controller
    {
        //Anyone can access
        [AllowAnonymous]
        public IActionResult AllAccess()
        {
            return View();
        }

        //Anyone with login can access
        [Authorize]
        public IActionResult AuthorizedAccess()
        {
            return View();
        }

        //Account with role of user can acess
        [Authorize(Roles = $"{SD.Admin},{SD.User}")]
        public IActionResult UserORAdminRoleAccess()
        {
            return View();
        }

        //Account with role of user can acess
        [Authorize(Policy = "AdminAndUser")]
        public IActionResult UserANDAdminRoleAccess()
        {
            return View();
        }

        //Account with role of admin can access
        [Authorize(Policy = "Admin")]
        public IActionResult AdminRoleAccess()
        {
            return View();
        }

        //Account with admin role and create claim can access
        [Authorize(Policy = "AdminRole_CreateClaim")]
        public IActionResult Admin_CreateAccess()
        {
            return View();
        }

        //Account with admin role and create,edit,delete claim can access
        [Authorize(Policy = "AdminRole_CreateEditDeleteClaim")]
        public IActionResult Admin_Creat_Edit_Delete_Access()
        {
            return View();
        }

        //Account with admin role and AdminRole_CreateEditDeleteClaim_OR_SuperAdminRole
        [Authorize(Policy = "AdminRole_CreateEditDeleteClaim_OR_SuperAdminRole")]
        public IActionResult AdminRole_CreateEditDeleteClaim_OR_SuperAdminRole()
        {
            return View();
        }

        [Authorize(Policy ="AdminWithMoreThan1000Days")]
        public IActionResult OnlyBhrugen()
        {
            return View();
        }

        [Authorize(Policy ="FirstNameAuth")]
        public IActionResult FirstNameAuth()
        {
            return View();
        }

    }
}
