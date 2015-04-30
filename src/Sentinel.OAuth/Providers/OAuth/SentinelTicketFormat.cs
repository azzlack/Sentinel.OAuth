namespace Sentinel.OAuth.Providers.OAuth
{
    using System;
    using System.Linq;
    using System.Security.Claims;
    using System.Security.Principal;

    using Microsoft.Owin.Security;

    using Sentinel.OAuth.Core.Interfaces.Providers;

    public class SentinelTicketFormat : ISecureDataFormat<AuthenticationTicket>
    {
        /// <summary>The principal provider.</summary>
        private readonly IPrincipalProvider principalProvider;

        /// <summary>
        ///     Initializes a new instance of the Sentinel.OAuth.Providers.OAuth.SentinelTicketFormat
        ///     class.
        /// </summary>
        /// <exception cref="ArgumentNullException">
        ///     Thrown when one or more required arguments are null.
        /// </exception>
        /// <param name="principalProvider">The principal provider.</param>
        public SentinelTicketFormat(IPrincipalProvider principalProvider)
        {
            if (principalProvider == null)
            {
                throw new ArgumentNullException("principalProvider");
            }

            this.principalProvider = principalProvider;
        }

        /// <summary>Protects the given data.</summary>
        /// <param name="data">The data.</param>
        /// <returns>A string.</returns>
        public string Protect(AuthenticationTicket data)
        {
            return string.Empty;
        }

        /// <summary>Unprotects.</summary>
        /// <param name="protectedText">The protected text.</param>
        /// <returns>An AuthenticationTicket.</returns>
        public AuthenticationTicket Unprotect(string protectedText)
        {
            return new AuthenticationTicket(new ClaimsIdentity(), new AuthenticationProperties());
        }
    }
}