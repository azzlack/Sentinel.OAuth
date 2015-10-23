namespace Sentinel.OAuth.Core.Models.OAuth.Http
{
    using Sentinel.OAuth.Core.Constants.Identity;
    using Sentinel.OAuth.Core.Interfaces.Identity;
    using System;
    using System.Collections.Generic;

    public class IdentityResponse : Dictionary<string, string>
    {
        /// <summary>Initializes a new instance of the <see cref="IdentityResponse" /> class.</summary>
        public IdentityResponse()
        {
        }

        /// <summary>Initializes a new instance of the <see cref="IdentityResponse" /> class.</summary>
        /// <param name="identity">The identity.</param>
        public IdentityResponse(ISentinelIdentity identity)
        {
            foreach (var claim in identity.Claims)
            {
                this.Add(claim.Type, claim.Value);
            }
        }

        /// <summary>Gets the identifier.</summary>
        /// <value>The identifier.</value>
        public string Id
        {
            get
            {
                if (this.ContainsKey("jti"))
                {
                    return this["jti"];
                }

                if (this.ContainsKey(ClaimType.Id))
                {
                    return this[ClaimType.Id];
                }

                return null;
            }
        }

        /// <summary>Gets the issuer.</summary>
        /// <value>The issuer.</value>
        public string Issuer
        {
            get
            {
                if (this.ContainsKey("iss"))
                {
                    return this["iss"];
                }

                if (this.ContainsKey(ClaimType.Issuer))
                {
                    return this[ClaimType.Issuer];
                }

                return null;
            }
        }

        /// <summary>Gets the subject.</summary>
        /// <value>The subject.</value>
        public string Subject
        {
            get
            {
                if (this.ContainsKey("sub"))
                {
                    return this["sub"];
                }

                if (this.ContainsKey(ClaimType.Name))
                {
                    return this[ClaimType.Name];
                }

                return null;
            }
        }

        /// <summary>Gets the audience.</summary>
        /// <value>The audience.</value>
        public string Audience
        {
            get
            {
                if (this.ContainsKey("aud"))
                {
                    return this["aud"];
                }

                if (this.ContainsKey(ClaimType.RedirectUri))
                {
                    return this[ClaimType.RedirectUri];
                }

                return null;
            }
        }

        /// <summary>Gets the expiration time.</summary>
        /// <value>The expiration time.</value>
        public DateTimeOffset ExpirationTime
        {
            get
            {
                DateTimeOffset exp;

                if (this.ContainsKey("exp") && DateTimeOffset.TryParse(this["exp"], out exp))
                {
                    return exp;
                }

                if (this.ContainsKey(ClaimType.Expiration) && DateTimeOffset.TryParse(ClaimType.Expiration, out exp))
                {
                    return exp;
                }

                return DateTimeOffset.MinValue;
            }
        }

        /// <summary>Gets the valid from time.</summary>
        /// <value>The valid from time.</value>
        public DateTimeOffset ValidFrom
        {
            get
            {
                DateTimeOffset nbf;

                if (this.ContainsKey("nbf") && DateTimeOffset.TryParse(this["nbf"], out nbf))
                {
                    return nbf;
                }

                if (this.ContainsKey(ClaimType.ValidFrom) && DateTimeOffset.TryParse(ClaimType.ValidFrom, out nbf))
                {
                    return nbf;
                }

                return DateTimeOffset.MinValue;
            }
        }

        /// <summary>Gets the created time.</summary>
        /// <value>The created time.</value>
        public DateTimeOffset Created
        {
            get
            {
                DateTimeOffset iat;

                if (this.ContainsKey("iat") && DateTimeOffset.TryParse(this["iat"], out iat))
                {
                    return iat;
                }

                if (this.ContainsKey(ClaimType.AuthenticationInstant) && DateTimeOffset.TryParse(ClaimType.AuthenticationInstant, out iat))
                {
                    return iat;
                }

                return DateTimeOffset.MinValue;
            }
        }
    }
}