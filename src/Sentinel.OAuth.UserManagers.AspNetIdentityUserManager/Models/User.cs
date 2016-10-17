namespace Sentinel.OAuth.UserManagers.AspNetIdentityUserManager.Models
{
    using System;
    using System.ComponentModel.DataAnnotations;

    using Microsoft.AspNet.Identity.EntityFramework;

    using Sentinel.OAuth.Core.Interfaces.Models;

    public class User : IdentityUser, IUser
    {
        public string UserId
        {
            get
            {
                return this.UserName;
            }

            set
            {
                this.UserName = value;
            }
        }

        public string Password
        {
            get
            {
                return this.PasswordHash;
            }

            set
            {
                this.PasswordHash = value;
            }
        }

        [Required]
        [MaxLength(100)]
        public string FirstName { get; set; }

        [Required]
        [MaxLength(100)]
        public string LastName { get; set; }

        public bool Enabled { get; set; }

        public DateTimeOffset LastLogin { get; set; }

        public object GetIdentifier()
        {
            return this.UserName;
        }

        public bool Equals(IUser other)
        {
            return this.GetIdentifier() == other.GetIdentifier();
        }
    }
}