namespace Sentinel.OAuth.Core.Models
{
    using Sentinel.OAuth.Core.Interfaces.Models;

    public class CreateUserResult
    {
        public IUser User { get; set; }

        public string Password { get; set; }
    }
}