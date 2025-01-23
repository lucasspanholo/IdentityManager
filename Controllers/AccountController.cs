using IndentityManager.Models;
using IndentityManager.Models.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using System.Security.Claims;
using System.Text.Encodings.Web;

namespace IndentityManager.Controllers
{
    public class AccountController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UrlEncoder _urlEncoder;


        public AccountController(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, UrlEncoder urlEncoder, RoleManager<IdentityRole> roleManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _urlEncoder = urlEncoder;
            _roleManager = roleManager;
        }
        public async Task<IActionResult> Register(string returnurl = null)
        {
            if (!_roleManager.RoleExistsAsync(SD.Admin).GetAwaiter().GetResult())
            {
                await _roleManager.CreateAsync(new IdentityRole(SD.Admin));
                await _roleManager.CreateAsync(new IdentityRole(SD.User));
            }

            ViewData["ReturnUrl"] = returnurl;
            //returnurl = returnurl ?? Url.Content("~/");
            RegisterViewModel registerViewModel = new()
            {
                RoleList = _roleManager.Roles.Select(x => x.Name).Select(i => new SelectListItem
                {
                    Text = i,
                    Value = i
                })
            };
            return View(registerViewModel);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model, string returnurl = null)
        {
            ViewData["ReturnUrl"] = returnurl;
            returnurl = returnurl ?? Url.Content("~/");
            if (ModelState.IsValid)
            {
                var user = new ApplicationUser
                {
                    UserName = model.Email,
                    Email = model.Email,
                    Name = model.Name,
                    DateCreated = DateTime.Now
                };
                var result = await _userManager.CreateAsync(user, model.Password);
                if (result.Succeeded)
                {
                    if(model.RoleSelected!=null && model.RoleSelected.Length>0 && model.RoleSelected == SD.Admin)
                    {
                        await _userManager.AddToRoleAsync(user, SD.Admin);
                    }
                    else
                    {
                        await _userManager.AddToRoleAsync(user, SD.User);
                    }
                    await _signInManager.SignInAsync(user, isPersistent: false);
                    return LocalRedirect(returnurl);
                }
                AddErrors(result);
            }
            model.RoleList = _roleManager.Roles.Select(x => x.Name).Select(i => new SelectListItem
            {
                Text = i,
                Value = i
            });

            return View(model);
        }

        public IActionResult Login()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model, string returnurl = null)
        {
            ViewData["ReturnUrl"] = returnurl;
            returnurl = returnurl ?? Url.Content("~/");

            if (ModelState.IsValid)
            {
                var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, lockoutOnFailure:true);
                if (result.Succeeded)
                {
                    var user = await _userManager.GetUserAsync(User);
                    var claim = await _userManager.GetClaimsAsync(user);

                    if (claim.Count > 0)
                    {
                        await _userManager.RemoveClaimAsync(user, claim.FirstOrDefault(u => u.Type == "FirstName"));
                    }
                    await _userManager.AddClaimAsync(user, new System.Security.Claims.Claim("FirstName", user.Name));

                    return LocalRedirect(returnurl);
                }
                if(result.RequiresTwoFactor)
                {
                    return RedirectToAction(nameof(VerifyAuthenticatorCode), new { ReturnUrl = returnurl, model.RememberMe });
                }                 
                if (result.IsLockedOut)
                {
                    return View("Lockout");
                }
                else
                {
                    ModelState.AddModelError(string.Empty, "Invalid login attempt. ");
                    return View(model);
                }
            }
            return View(model);
        }

        [HttpGet]
        public async Task<IActionResult> VerifyAuthenticatorCode(bool rememberMe, string returnUrl = null)
        {
            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if(user == null)
            {
                return View("Error");
            }
            ViewData["ReturnUrl"] = returnUrl;
            return View(new VerifyAuthenticatorViewModel { ReturnUrl = returnUrl, RememberMe = rememberMe});
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> VerifyAuthenticatorCode(VerifyAuthenticatorViewModel model)
        {
            model.ReturnUrl = model.ReturnUrl ?? Url.Content("~/");
            if (!ModelState.IsValid)
            {
                return View(model);
            }
            var result = await _signInManager.TwoFactorAuthenticatorSignInAsync(model.Code, model.RememberMe, rememberClient:false);
            if (result.Succeeded)
            {
                return LocalRedirect(model.ReturnUrl);
            }
            if (result.IsLockedOut)
            {
                return View("Lockout");
            }
            else
            {
                ModelState.AddModelError(string.Empty, "Invalid login attempt. ");
                return View(model);
            }
        }

        [HttpGet]
        public async Task<IActionResult> RemoveAuthenticator()
        {
            var user = await _userManager.GetUserAsync(User);
            await _userManager.ResetAuthenticatorKeyAsync(user);
            await _userManager.SetTwoFactorEnabledAsync(user, false);
            return RedirectToAction(nameof(Index), "Home");
        }

        [HttpGet]
        public IActionResult Lockout()
        {
            return View();
        } 

        [HttpGet]
        [AllowAnonymous]
        public IActionResult NoAcess()
        {
            return View();
        }
        
        [HttpGet]
        public IActionResult ForgotPassword()
        {
            return View();
        }     
        
        [HttpGet]
        public IActionResult AuthenticatorConfirmation()
        {
            return View();
        }        

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
            return View(model);
        }

        [HttpGet]
        [Authorize]
        public async Task<IActionResult> EnableAuthenticator()
        {
            string AuthenticatorUriFormat = "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6";
            var user = await _userManager.GetUserAsync(User);
            await _userManager.ResetAuthenticatorKeyAsync(user);
            var token = await _userManager.GetAuthenticatorKeyAsync(user);
            string AuthUri = string.Format(AuthenticatorUriFormat, _urlEncoder.Encode("IdentityManager"), _urlEncoder.Encode(user.Email), token);
            var model = new TwoFactorAuthenticationViewModel() { Token = token, QRCodeUrl = AuthUri };
            return View(model);
        }

        [HttpPost]
        [Authorize]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> EnableAuthenticator (TwoFactorAuthenticationViewModel model)
        {
            if(ModelState.IsValid)
            {
                var user = await _userManager.GetUserAsync(User);
                var suceeded = await _userManager.VerifyTwoFactorTokenAsync(user, _userManager.Options.Tokens.AuthenticatorTokenProvider, model.Code);
                if (suceeded)
                {
                    await _userManager.SetTwoFactorEnabledAsync(user, true);
                }
                else
                {
                    ModelState.AddModelError("Verify", "Not Validated");
                    return View(model);
                }
                return RedirectToAction(nameof(AuthenticatorConfirmation));

            }
            return View("Error");
        }



        private void AddErrors(IdentityResult result)
        {
            foreach(var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> LogOff()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction("Index", "Home");
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public IActionResult ExternalLogin(string provider, string returnUrl = null)
        {
            var redirectUrl = Url.Action("ExternalLoginCallback", "Account", new { returnUrl });
            var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);
            return Challenge(properties, provider);
        }

        [HttpGet]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ExternalLoginCallback(string returnurl = null, string remoteError = null)
        {
            returnurl = returnurl ?? Url.Content("~/");
            if (remoteError != null)
            {
                ModelState.AddModelError(string.Empty, $"errro from external provider: {remoteError}");
                return View(nameof(Login));
            }

            var info = await _signInManager.GetExternalLoginInfoAsync();
            if (info == null) { return RedirectToAction(nameof(Login)); }

            var result = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false, bypassTwoFactor: true);

            if (result.Succeeded)
            {
                await _signInManager.UpdateExternalAuthenticationTokensAsync(info);
                return LocalRedirect(returnurl);
            }
            if (result.RequiresTwoFactor)
            {
                return RedirectToAction(nameof(VerifyAuthenticatorCode), new { returnurl });
            }
            else
            {
                //user account is not created

                ViewData["ReturnUrl"] = returnurl;
                ViewData["ProviderDisplayName"] = info.ProviderDisplayName;

                return View("ExternalLoginConfirmation", new ExternalLoginConfirmationViewModel
                {
                    Email = info.Principal.FindFirstValue(ClaimTypes.Email),
                    Name = info.Principal.FindFirstValue(ClaimTypes.Name)
                });
            }

        }

            [HttpPost]
            [AllowAnonymous]
            [ValidateAntiForgeryToken]
            public async Task<IActionResult> ExternalLoginConfirmation(ExternalLoginConfirmationViewModel model,string returnurl = null)
            {
                returnurl = returnurl ?? Url.Content("~/");

                if (ModelState.IsValid) {
                    var info = await _signInManager.GetExternalLoginInfoAsync();
                    if (info == null)
                    {
                        return View("Error");
                    }
                    var user = new ApplicationUser
                    {
                        UserName = model.Email,
                        Email = model.Email,
                        Name = model.Name,
                        NormalizedEmail = model.Email.ToUpper(),
                        DateCreated = DateTime.Now
                    };

                    var result = await _userManager.CreateAsync(user);
                    if (result.Succeeded)
                    {
                        await _userManager.AddToRoleAsync(user, SD.User);
                        result = await _userManager.AddLoginAsync(user, info);
                        if (result.Succeeded)
                        {
                            await _signInManager.SignInAsync(user, isPersistent: false);
                            await _signInManager.UpdateExternalAuthenticationTokensAsync(info);
                            return LocalRedirect(returnurl);
                        }
                    }
                    AddErrors(result);
                }
                ViewData["ReturnUrl"] = returnurl;
                return View(model);
            }
        }
}
