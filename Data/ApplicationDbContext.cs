using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using IndentityManager.Models;
namespace IndentityManager.Data
{
    public class ApplicationDbContext : IdentityDbContext
    {
       public ApplicationDbContext(DbContextOptions options) : base(options) { }


        public DbSet<ApplicationUser> ApplicationUsers { get; set; }



    }
}
