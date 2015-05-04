namespace Sentinel.OAuth.Models.Identity
{
    using System;
    using System.Diagnostics;
    using System.Linq;
    using System.Security.Claims;
    using System.Security.Principal;

    using Sentinel.OAuth.Core.Constants.Identity;
    using Sentinel.OAuth.Core.Interfaces.Identity;

    /// <summary>A JSON-serializable principal.</summary>
    [DebuggerDisplay("Identity: {Identity}")]
    public class SentinelPrincipal : ISentinelPrincipal
    {
        /// <summary>
        ///     Initializes a new instance of the Sentinel.OAuth.Core.Models.Identity.SentinelPrincipal
        ///     class.
        /// </summary>
        public SentinelPrincipal()
        {
            this.Identity = new SentinelIdentity(string.Empty);
        }

        /// <summary>
        ///     Initializes a new instance of the Sentinel.OAuth.Core.Models.Identity.JsonPrincipal
        ///     class.
        /// </summary>
        /// <exception cref="System.ArgumentNullException">
        ///     Thrown when one or more required arguments are null.
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
        {
            if (principal.Identity == null)
            {
                throw new ArgumentNullException("principal", "Supplied Principal does not contain an identity");
            }

            this.Identity = new SentinelIdentity(principal.Identity);
        }

        /// <summary>Gets the identity.</summary>
        /// <value>The identity.</value>
        IIdentity IPrincipal.Identity
        {
            get
            {
                return this.Identity;
            }
        }

        /// <summary>
        /// Gets the actual identity.
        /// </summary>
        /// <value>The actual identity.</value>
        public ISentinelIdentity Identity { get; private set; }

        /// <summary>Gets an unauthorized/anonymous Sentinel principal object.</summary>
        /// <value>An unauthorized/anonymous Sentinel principal object.</value>
        public static ISentinelPrincipal Anonymous
        {
            get
            {
                return new SentinelPrincipal(SentinelIdentity.Anonymous);
            }
        }

        /// <summary>Gets the current principal.</summary>
        /// <value>The current principal.</value>
        public static ISentinelPrincipal Current
        {
            get
            {
                return new SentinelPrincipal(ClaimsPrincipal.Current);
            }
        }

        /// <summary>Determines whether the current principal belongs to the specified role.</summary>
        /// <param name="role">The name of the role for which to check membership.</param>
        /// <returns>
        ///     true if the current principal is a member of the specified role; otherwise, false.
        /// </returns>
        public bool IsInRole(string role)
        {
            return this.Identity.Claims.Any(x => x.Type == ClaimType.Role && x.Value == role);
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