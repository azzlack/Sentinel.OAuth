namespace Sentinel.OAuth.Client.Mvc5.Models
{
    using System.Collections.Generic;
    using System.ComponentModel;
    using System.ComponentModel.DataAnnotations;

    public class LoginModel
    {
        public LoginModel()
        {
            this.RememberMe = true;
        }

        [DisplayName("Username or email")]
        [Required(ErrorMessage = "Please enter an username or email")]
        public string Username { get; set; }

        [Required(ErrorMessage = "Please enter a password")]
        public string Password { get; set; }

        [DisplayName("Remember me")]
        [DefaultValue(true)]
        public bool RememberMe { get; set; }

        public string ReturnUrl { get; set; }

        public IEnumerable<string> Errors { get; set; }

    }
}