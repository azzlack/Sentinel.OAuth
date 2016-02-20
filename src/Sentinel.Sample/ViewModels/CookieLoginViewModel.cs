namespace Sentinel.Sample.ViewModels
{
    using System.ComponentModel;
    using System.ComponentModel.DataAnnotations;

    public class CookieLoginViewModel
    {
        [DisplayName("Username or email")]
        [Required(ErrorMessage = "Please enter an username")]
        public string Username { get; set; }

        [Required(ErrorMessage = "Please enter a password")]
        public string Password { get; set; }

        public string ReturnUrl { get; set; }
    }
}