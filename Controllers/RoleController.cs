﻿using IndentityManager.Data;
using IndentityManager.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace IndentityManager.Controllers
{
    public class RoleController : Controller
    {
        private readonly ApplicationDbContext _db;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public RoleController(ApplicationDbContext db, UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager)
        {
            _db = db;
            _userManager = userManager;
            _roleManager = roleManager;
        }

        public IActionResult Index()
        {

            var roles = _db.Roles.ToList();
            return View(roles);
        }

        [HttpGet]
        public IActionResult Upsert(string roleId)
        {
            if (String.IsNullOrWhiteSpace(roleId))
            {
                return View();
            }
            else
            {
                var objFromDb = _db.Roles.FirstOrDefault(r => r.Id == roleId);
                return View();
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Upsert(IdentityRole roleObj)
        {
            if (await _roleManager.RoleExistsAsync(roleObj.Name))
            {
                //error
            }
            if (String.IsNullOrEmpty(roleObj.NormalizedName))
            {
                //create
                await _roleManager.CreateAsync(new IdentityRole() { Name = roleObj.Name });
                TempData[SD.Sucess] = "Role created successfully";
            }
            else
            {
                //update
                var objFromDb = _db.Roles.FirstOrDefault(u => u.Id == roleObj.Id);
                objFromDb.Name = roleObj.Name;
                objFromDb.NormalizedName = roleObj.Name.ToUpper();
                var result = await _roleManager.UpdateAsync(objFromDb);
                TempData[SD.Sucess] = "Role updated successfully";

            }
            return RedirectToAction(nameof(Index));
        }


        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Policy = "OnlySuperAdminChecker")]
        public async Task<IActionResult> Delete(string roleId)
        {

            var objFromDb = _db.Roles.FirstOrDefault(u => u.Id == roleId);
            if (objFromDb != null)
            {

                var userRolesForThisRole = _db.UserRoles.Where(u => u.RoleId == roleId).Count();
                if(userRolesForThisRole > 0)
                {
                    TempData[SD.Error] = "Cannot delete this role, since there are users assigned to this role.";
                    return RedirectToAction(nameof(Index));
                }

                var result = await _roleManager.DeleteAsync(objFromDb);
                TempData[SD.Sucess] = "Role deleted successfully";
            }
            return RedirectToAction(nameof(Index));
        }

    }
}