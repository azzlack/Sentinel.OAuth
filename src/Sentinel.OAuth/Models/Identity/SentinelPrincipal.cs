namespace Sentinel.OAuth.Models.Identity
{
    using Sentinel.OAuth.Core.Constants.Identity;
    using Sentinel.OAuth.Core.Extensions;
    using Sentinel.OAuth.Core.Interfaces.Identity;
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Linq;
    using System.Security.Claims;
    using System.Security.Principal;
    using System.Threading;

    /// <summary>A JSON-serializable principal.</summary>
    [DebuggerDisplay("Identity: {Identity}")]
    public class SentinelPrincipal : ISentinelPrincipal
    {
        /// <summary>
        /// Initializes a new instance of the Sentinel.OAuth.Models.Identity.SentinelPrincipal class.
        /// </summary>
        public SentinelPrincipal()
        {
            this.Identity = new SentinelIdentity(string.Empty);
        }

        /// <summary>
        /// Initializes a new instance of the Sentinel.OAuth.Models.Identity.SentinelPrincipal class.
        /// </summary>
        /// <exception cref="ArgumentNullException">
        /// Thrown when one or more required arguments are null.
        /// </exception>
        /// <param name="identity">The identity.</param>
        public SentinelPrincipal(ISentinelIdentity identity)
        {
            if (identity == null)
            {
                throw new ArgumentNullException("identity");
            }

            this.Identity = identity;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="SentinelPrincipal" /> class.
        /// </summary>
        /// <param name="principal">The principal.</param>
        public SentinelPrincipal(IPrincipal principal)
            : this(principal.Identity)
        {
        }

        /// <summary>
        /// Initializes a new instance of the Sentinel.OAuth.Models.Identity.SentinelPrincipal class.
        /// </summary>
        /// <exception cref="ArgumentNullException">
        /// Thrown when one or more required arguments are null.
        /// </exception>
        /// <param name="identity">The identity.</param>
        public SentinelPrincipal(IIdentity identity)
        {
            if (identity == null)
            {
                throw new ArgumentNullException(nameof(identity));
            }

            this.Identity = new SentinelIdentity(identity);
        }

        /// <summary>Gets an unauthorized/anonymous Sentinel principal object.</summary>
        /// <value>An unauthorized/anonymous Sentinel principal object.</value>
        public static ISentinelPrincipal Anonymous => new SentinelPrincipal(SentinelIdentity.Anonymous);

        /// <summary>Gets the current principal.</summary>
        /// <value>The current principal.</value>
        public static ISentinelPrincipal Current => new SentinelPrincipal(Thread.CurrentPrincipal);

        /// <summary>Gets the identity.</summary>
        /// <value>The identity.</value>
        IIdentity IPrincipal.Identity => this.Identity ?? SentinelIdentity.Anonymous;

        /// <summary>Gets the time in UTC format when the identity expires.</summary>
        /// <value>The expire time in UTC format.</value>
        public DateTimeOffset ValidTo
        {
            get
            {
                var expireClaim = this.Identity.Claims.FirstOrDefault(x => x.Type == ClaimTypes.Expiration || x.Type == JwtClaimType.ExpirationTime);

                long unixTime;
                if (expireClaim != null && long.TryParse(expireClaim.Value, out unixTime))
                {
                    return unixTime.ToDateTimeOffset();
                }

                return DateTimeOffset.MinValue;
            }
        }

        /// <summary>Gets the roles.</summary>
        /// <value>The roles.</value>
        public IEnumerable<string> Roles
        {
            get
            {
                return this.Identity.Claims.Where(x => x.Type == ClaimTypes.Role).Select(x => x.Value);
            }
        }

        /// <summary>
        /// Gets the actual identity.
        /// </summary>
        /// <value>The actual identity.</value>
        public ISentinelIdentity Identity { get; }

        /// <summary>Determines whether the current principal belongs to the specified role.</summary>
        /// <param name="role">The name of the role for which to check membership.</param>
        /// <returns>
        ///     true if the current principal is a member of the specified role; otherwise, false.
        /// </returns>
        public bool IsInRole(string role)
        {
            return this.Identity.Claims.Any(x => x.Type == ClaimTypes.Role && x.Value == role);
        }

        /// <summary>
        /// Returns a <see cref="string" /> that represents this instance.
        /// </summary>
        /// <returns>A <see cref="string" /> that represents this instance.</returns>
        public override string ToString()
        {
            return this.Identity.ToString();
        }
    }
}