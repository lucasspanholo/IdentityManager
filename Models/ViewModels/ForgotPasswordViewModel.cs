using System.ComponentModel.DataAnnotations;

namespace IndentityManager.Models.ViewModels
{
    public class ForgotPasswordViewModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }

    }
}
