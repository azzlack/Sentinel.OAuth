namespace Sentinel.OAuth.UserManagers.SqlServerUserManager.Models
{
    using System;

    public class User
    {
        public string Username { get; set; } 

        public string Password { get; set; }

        public string FirstName { get; set; }

        public string LastName { get; set; }

        public DateTime LastLogin { get; set; }
    }
}