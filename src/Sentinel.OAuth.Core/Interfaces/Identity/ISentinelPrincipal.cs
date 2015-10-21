namespace Sentinel.OAuth.Core.Interfaces.Identity
{
    using System;
    using System.Collections.Generic;
    using System.Security.Principal;

    /// <summary>Defines the basic functionality of a Principal object.</summary>
    public interface ISentinelPrincipal : IPrincipal
    {
        /// <summary>Gets the Sentinel identity.</summary>
        /// <value>The Sentinel identity.</value>
        new ISentinelIdentity Identity { get; }

        /// <summary>Gets the time in UTC format when the identity expires.</summary>
        /// <value>The expire time in UTC format.</value>
        DateTimeOffset ValidTo { get; }

        /// <summary>Gets the roles.</summary>
        /// <value>The roles.</value>
        IEnumerable<string> Roles { get; }

        /// <summary>Gets the access token.</summary>
        /// <value>The access token.</value>
        string AccessToken { get; }

        /// <summary>Gets the refresh token.</summary>
        /// <value>The refresh token.</value>
        string RefreshToken { get; }
    }
}