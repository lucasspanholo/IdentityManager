using Microsoft.AspNetCore.Authorization;

namespace IndentityManager.Authorize
{
    public class FirstNameAuthRequirement : IAuthorizationRequirement
    {
        public FirstNameAuthRequirement(string name)
        {
            Name = name;
        }

        public string Name { get; set; }
    }
}
