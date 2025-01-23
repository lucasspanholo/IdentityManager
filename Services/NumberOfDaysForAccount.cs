using IndentityManager.Data;
using IndentityManager.Services.IServices;

namespace IndentityManager.Services
{
    public class NumberOfDaysForAccount : INumberOfDaysForAccount
    {
        private readonly ApplicationDbContext _context;

        public NumberOfDaysForAccount(ApplicationDbContext context)
        {
            _context = context;
        }

        public int Get(string userId)
        {
            var user = _context.ApplicationUsers.FirstOrDefault(u => u.Id == userId);
            if(user!=null && user.DateCreated != DateTime.MinValue)
            {
                return(DateTime.Today - user.DateCreated).Days;
            }
            return 0;
        }
    }
}
