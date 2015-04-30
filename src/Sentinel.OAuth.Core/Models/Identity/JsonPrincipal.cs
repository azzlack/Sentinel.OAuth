namespace Sentinel.OAuth.Core.Models.Identity
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Linq;
    using System.Security.Claims;

    /// <summary>A JSON-serializable principal.</summary>
    [DebuggerDisplay("Identity: {Identity}")]
    public class JsonPrincipal
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="JsonPrincipal" /> class.
        /// </summary>
        public JsonPrincipal()
        {
            this.Identities = new List<JsonIdentity>();
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="JsonPrincipal" /> class.
        /// </summary>
        /// <param name="principal">The principal.</param>
        public JsonPrincipal(ClaimsPrincipal principal)
        {
            if (principal.Identity == null)
            {
                throw new ArgumentNullException("principal", "Supplied Principal does not contain an identity");
            }

            this.Identities = principal.Identities.Select(x => new JsonIdentity(x));
        }

        /// <summary>
        /// Gets the claims.
        /// </summary>
        /// <value>The claims.</value>
        public IEnumerable<JsonClaim> Claims
        {
            get
            {
                return this.Identity != null ? this.Identity.Claims : Enumerable.Empty<JsonClaim>();
            }
        }

        /// <summary>
        /// Gets the identity.
        /// </summary>
        /// <value>The identity.</value>
        public JsonIdentity Identity
        {
            get
            {
                return this.Identities.FirstOrDefault();
            }
        }

        /// <summary>
        /// Gets or sets the identities.
        /// </summary>
        /// <value>The identities.</value>
        public IEnumerable<JsonIdentity> Identities { get; set; }

        /// <summary>
        /// Performs an implicit conversion from <see cref="JsonPrincipal"/> to <see cref="ClaimsPrincipal"/>.
        /// </summary>
        /// <param name="principal">The principal.</param>
        /// <returns>The result of the conversion.</returns>
        public static implicit operator ClaimsPrincipal(JsonPrincipal principal)
        {
            if (principal.Identity == null)
            {
                throw new ArgumentNullException("principal", "Supplied Principal does not contain an identity");
            }

            return new ClaimsPrincipal((ClaimsIdentity)principal.Identity);
        }

        /// <summary>
        /// Performs an explicit conversion from <see cref="ClaimsPrincipal"/> to <see cref="JsonPrincipal"/>.
        /// </summary>
        /// <param name="m">The principal.</param>
        /// <returns>The result of the conversion.</returns>
        public static explicit operator JsonPrincipal(ClaimsPrincipal m)
        {
            return new JsonPrincipal(m);
        }

        /// <summary>
        /// Returns a <see cref="System.String" /> that represents this instance.
        /// </summary>
        /// <returns>A <see cref="System.String" /> that represents this instance.</returns>
        public override string ToString()
        {
            return string.Join(", ", this.Identities);
        }
    }
}