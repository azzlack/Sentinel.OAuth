namespace Sentinel.OAuth.Core.Constants.Identity
{
    public class ClaimType
    {
        /// <summary>The scope claim type.</summary>
        public const string Scope = "urn:oauth:scope";

        /// <summary>The client claim type.</summary>
        public const string Client = "urn:oauth:client";

        /// <summary>The grant type claim type.</summary>
        public const string GrantType = "urn:oauth:granttype";

        /// <summary>The redirect uri claim type.</summary>
        public const string RedirectUri = "urn:oauth:redirecturi";

        /// <summary>The id claim type.</summary>
        public const string Id = "urn:oauth:id";

        /// <summary>The issuer claim type.</summary>
        public const string Issuer = "urn:oauth:issuer";

        /// <summary>The valid from claim type.</summary>
        public const string ValidFrom = "urn:oauth:validfrom";

        /// <summary>The authentication source claim type.</summary>
        public const string AuthenticationSource = "urn:sentinel:authenticationsource";

        /// <summary>The identity provider claim type.</summary>
        public const string IdentityProvider = "http://schemas.microsoft.com/accesscontrolservice/2010/07/claims/identityprovider";

        /// <summary>The name claim type.</summary>
        public const string Name = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name";

        /// <summary>The expiration claim type.</summary>
        public const string Expiration = "http://schemas.microsoft.com/ws/2008/06/identity/claims/expiration";

        /// <summary>The authentication instant claim type.</summary>
        public const string AuthenticationInstant = "http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationinstant";
    }
}