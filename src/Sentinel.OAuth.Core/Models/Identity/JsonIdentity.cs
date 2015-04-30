namespace Sentinel.OAuth.Core.Models.Identity
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Linq;
    using System.Security.Claims;
    using System.Security.Principal;

    /// <summary>A JSON-serializable identity.</summary>
    [DebuggerDisplay("AuthenticationType: {AuthenticationType}, Label: {Label}, RoleClaimType: {RoleClaimType}, NameClaimType: {NameClaimType}, IsAuthenticated: {IsAuthenticated}, Name: {Name}, Claims: {Claims.Count()}")]
    public class JsonIdentity
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="JsonIdentity"/> class.
        /// </summary>
        public JsonIdentity()
        {
            this.Claims = new List<JsonClaim>();
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="JsonIdentity"/> class.
        /// </summary>
        /// <param name="identity">The identity.</param>
        public JsonIdentity(ClaimsIdentity identity)
        {
            if (identity == null)
            {
                throw new ArgumentNullException("identity");
            }

            this.Name = identity.Name;
            this.IsAuthenticated = identity.IsAuthenticated;
            this.Label = identity.Label;
            this.NameClaimType = identity.NameClaimType;
            this.RoleClaimType = identity.RoleClaimType;
            this.AuthenticationType = identity.AuthenticationType;

            if (identity.Claims != null)
            {
                this.Claims = identity.Claims.Select(x => new JsonClaim(x));
            }
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="JsonIdentity"/> class.
        /// </summary>
        /// <param name="identity">The identity.</param>
        public JsonIdentity(IIdentity identity)
        {
            if (identity == null)
            {
                throw new ArgumentNullException("identity");
            }

            var claimsIdentity = identity as ClaimsIdentity;

            if (claimsIdentity != null)
            {
                this.Name = claimsIdentity.Name;
                this.IsAuthenticated = claimsIdentity.IsAuthenticated;
                this.Label = claimsIdentity.Label;
                this.NameClaimType = claimsIdentity.NameClaimType;
                this.RoleClaimType = claimsIdentity.RoleClaimType;
                this.AuthenticationType = claimsIdentity.AuthenticationType;

                if (claimsIdentity.Claims != null)
                {
                    this.Claims = claimsIdentity.Claims.Select(x => new JsonClaim(x));
                }
            }
        }

        /// <summary>
        /// Gets or sets the type of the authentication.
        /// </summary>
        /// <value>The type of the authentication.</value>
        public string AuthenticationType { get; set; }

        /// <summary>
        /// Gets or sets the claims.
        /// </summary>
        /// <value>The claims.</value>
        public IEnumerable<JsonClaim> Claims { get; set; }

        /// <summary>
        /// Gets or sets the label.
        /// </summary>
        /// <value>The label.</value>
        public string Label { get; set; }

        /// <summary>
        /// Gets or sets the type of the role identity.
        /// </summary>
        /// <value>The type of the role identity.</value>
        public string RoleClaimType { get; set; }

        /// <summary>
        /// Gets or sets the type of the name identity.
        /// </summary>
        /// <value>The type of the name identity.</value>
        public string NameClaimType { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether this instance is authenticated.
        /// </summary>
        /// <value><c>true</c> if this instance is authenticated; otherwise, <c>false</c>.</value>
        public bool IsAuthenticated { get; set; }

        /// <summary>
        /// Gets or sets the name.
        /// </summary>
        /// <value>The name.</value>
        public string Name { get; set; }

        /// <summary>
        /// Adds the claim.
        /// </summary>
        /// <param name="claim">The claim.</param>
        public void AddClaim(Claim claim)
        {
            this.AddClaim((JsonClaim)claim);
        }

        /// <summary>
        /// Adds the claim.
        /// </summary>
        /// <param name="claim">The claim.</param>
        public void AddClaim(JsonClaim claim)
        {
            var claims = this.Claims.ToList();
            claims.Add(claim);

            this.Claims = claims;
        }

        /// <summary>
        /// Performs an implicit conversion from <see cref="JsonIdentity" /> to <see cref="ClaimsIdentity" />.
        /// </summary>
        /// <param name="identity">The identity.</param>
        /// <returns>The result of the conversion.</returns>
        public static implicit operator ClaimsIdentity(JsonIdentity identity)
        {
            if (identity == null)
            {
                throw new ArgumentNullException("identity");
            }

            if (identity.Claims == null || !identity.Claims.Any())
            {
                throw new ArgumentNullException("identity", "Supplied Identity does not contain any Claims");
            }

            return new ClaimsIdentity(identity.Claims.Select(x => (Claim)x), identity.AuthenticationType, identity.NameClaimType, identity.RoleClaimType);
        }

        /// <summary>
        /// Performs an explicit conversion from <see cref="Claim"/> to <see cref="JsonClaim"/>.
        /// </summary>
        /// <param name="m">The identity.</param>
        /// <returns>The result of the conversion.</returns>
        public static explicit operator JsonIdentity(ClaimsIdentity m)
        {
            return new JsonIdentity(m);
        }

        /// <summary>
        /// Returns a <see cref="System.String" /> that represents this instance.
        /// </summary>
        /// <returns>A <see cref="System.String" /> that represents this instance.</returns>
        public override string ToString()
        {
            return
                string.Format(
                    "AuthenticationType: {0}, Label: {1}, RoleClaimType: {2}, NameClaimType: {3}, IsAuthenticated: {4}, Name: {5}, Claims: [{6}]",
                    this.AuthenticationType,
                    this.Label,
                    this.RoleClaimType,
                    this.NameClaimType,
                    this.IsAuthenticated,
                    this.Name,
                    this.Claims != null ? string.Join(", ", this.Claims) : string.Empty);
        }
    }
}