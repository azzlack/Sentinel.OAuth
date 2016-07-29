namespace Sentinel.OAuth.Core.Models.OAuth
{
    using Sentinel.OAuth.Core.Interfaces.Models;
    using System;

    public class User : IUser
    {
        /// <summary>Initializes a new instance of the <see cref="User" /> class.</summary>
        public User()
        {
        }

        /// <summary>Initializes a new instance of the <see cref="User" /> class.</summary>
        /// <param name="user">The user.</param>
        public User(IUser user)
        {
            this.UserId = user.UserId;
            this.Password = user.Password;
            this.FirstName = user.FirstName;
            this.LastName = user.LastName;
            this.Enabled = user.Enabled;
            this.LastLogin = user.LastLogin;
        }

        /// <summary>Gets or sets the identifier of the user.</summary>
        /// <value>The identifier of the user.</value>
        public string UserId { get; set; }

        /// <summary>Gets or sets the password.</summary>
        /// <value>The password.</value>
        public string Password { get; set; }

        /// <summary>Gets or sets the person's first name.</summary>
        /// <value>The name of the first.</value>
        public string FirstName { get; set; }

        /// <summary>Gets or sets the person's last name.</summary>
        /// <value>The name of the last.</value>
        public string LastName { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether this Client is enabled.
        /// </summary>
        /// <value><c>true</c> if enabled; otherwise, <c>false</c>.</value>
        public bool Enabled { get; set; }

        /// <summary>Gets or sets the last login.</summary>
        /// <value>The last login.</value>
        public DateTimeOffset LastLogin { get; set; }

        /// <summary>Gets the identifier.</summary>
        /// <returns>The identifier.</returns>
        public virtual object GetIdentifier()
        {
            return this.UserId;
        }

        /// <summary>
        /// Indicates whether the current object is equal to another object of the same type.
        /// </summary>
        /// <returns>
        /// true if the current object is equal to the <paramref name="other"/> parameter; otherwise, false.
        /// </returns>
        /// <param name="other">An object to compare with this object.</param>
        public virtual bool Equals(IUser other)
        {
            return this.UserId == other.UserId;
        }
    }
}