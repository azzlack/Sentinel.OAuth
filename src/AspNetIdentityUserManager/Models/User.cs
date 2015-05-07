namespace Sentinel.OAuth.UserManagers.AspNetIdentityUserManager.Models
{
    using System.ComponentModel.DataAnnotations;

    using Microsoft.AspNet.Identity.EntityFramework;

    public class User : IdentityUser
    {
        [Required]
        [MaxLength(100)]
        public string FirstName { get; set; }

        [Required]
        [MaxLength(100)]
        public string LastName { get; set; }
    }
}