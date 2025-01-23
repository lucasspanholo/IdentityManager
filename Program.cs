using IndentityManager;
using IndentityManager.Authorize;
using IndentityManager.Data;
using IndentityManager.Models;
using IndentityManager.Services;
using IndentityManager.Services.IServices;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();

builder.Services.AddDbContext<ApplicationDbContext>(options => options.UseNpgsql(   
    builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>().AddDefaultTokenProviders();

builder.Services.AddScoped<INumberOfDaysForAccount, NumberOfDaysForAccount>();
builder.Services.AddScoped<IAuthorizationHandler, AdminWithOver1000DaysHandler>();
builder.Services.AddScoped<IAuthorizationHandler, FirstNameAuthHandler>();

builder.Services.ConfigureApplicationCookie(opt =>
{
    opt.AccessDeniedPath = new PathString("/Account/NoAcess)");
});

builder.Services.Configure<IdentityOptions>(opt =>
{
    opt.Password.RequireDigit = false;
    opt.Password.RequireLowercase = false;
    opt.Password.RequireNonAlphanumeric = false;
    opt.Lockout.MaxFailedAccessAttempts = 3;
    opt.SignIn.RequireConfirmedEmail = false;
});

builder.Services.AddAuthorization(opt =>
{
    opt.AddPolicy("Admin", policy => policy.RequireRole(SD.Admin));
    opt.AddPolicy("AdminAndUser", policy => policy.RequireRole(SD.Admin).RequireRole(SD.User));
    opt.AddPolicy("AdminRole_CreateClaim", policy => policy.RequireRole(SD.Admin).RequireClaim("Create", "True"));
    opt.AddPolicy("AdminRole_CreateEditDeleteClaim", policy => policy
        .RequireRole(SD.Admin)
        .RequireClaim("Create", "True")
        .RequireClaim("Edit", "True")
        .RequireClaim("Delete", "True"));
    opt.AddPolicy("AdminRole_CreateEditDeleteClaim_OR_SuperAdminRole", policy => policy.RequireAssertion(context => (
        context.User.IsInRole(SD.Admin) && context.User.HasClaim(c => c.Type == "Create" && c.Value == "True") &&
        context.User.IsInRole(SD.Admin) && context.User.HasClaim(c => c.Type == "Edit" && c.Value == "True") &&
        context.User.IsInRole(SD.Admin) && context.User.HasClaim(c => c.Type == "Delete" && c.Value == "True")) ||
        context.User.IsInRole(SD.SuperAdmin)));
    //passar tudo isso pra um metodo fora do programcs e somente retornar o metodo

    opt.AddPolicy("OnlySuperAdminChecker", p => p.Requirements.Add(new OnlySuperAdminChecker()));
    opt.AddPolicy("AdminWithMoreThan1000Days", p => p.Requirements.Add(new AdminWithMoreThan1000DaysRequirement(1000)));
    opt.AddPolicy("FirstNameAuth", p => p.Requirements.Add(new FirstNameAuthRequirement("test")));
});


builder.Services.AddAuthentication().AddMicrosoftAccount(opt =>
{
    opt.ClientId = "***********";
    opt.ClientSecret = "***********";
});

builder.Services.AddAuthentication().AddFacebook(opt =>
{
    opt.ClientId = "***********";
    opt.ClientSecret = "***********";
});


var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
