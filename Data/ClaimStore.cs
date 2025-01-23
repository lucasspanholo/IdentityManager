using System.Security.Claims;

namespace IndentityManager.Data
{
    public class ClaimStore
    {
        public static List<Claim> claimsList =
            [
                new Claim("Create", "Create"),
                new Claim("Edit", "Edit"),
                new Claim("Delete", "Delete"),
            ];
    }
}
