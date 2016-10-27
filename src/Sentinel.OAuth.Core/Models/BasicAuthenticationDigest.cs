namespace Sentinel.OAuth.Core.Models
{
    using System;
    using System.Linq;
    using System.Net;

    public class BasicAuthenticationDigest
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="BasicAuthenticationDigest" /> class.
        /// </summary>
        /// <param name="userId">The identifier.</param>
        /// <param name="password">The password.</param>
        public BasicAuthenticationDigest(string userId, string password)
        {
            this.UserId = userId;
            this.Password = password;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="BasicAuthenticationDigest" />
        ///  class.
        /// </summary>
        /// <param name="userId">The identifier.</param>
        /// <param name="cipher">The cipher.</param>
        public BasicAuthenticationDigest(string userId, BasicAuthenticationCipher cipher)
        {
            this.UserId = userId;
            this.Password = cipher.ToString();
        }

        /// <summary>Gets the identifier.</summary>
        /// <value>The identifier.</value>
        public string UserId { get; }

        /// <summary>Gets the password of the user.</summary>
        /// <value>The password of the user.</value>
        public string Password { get; }

        /// <summary>Parses the password.</summary>
        /// <returns>The parsed password.</returns>
        public BasicAuthenticationCipher GetCipher()
        {
            return new BasicAuthenticationCipher(this.Password);
        }
    }
}