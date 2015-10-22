namespace Sentinel.OAuth.Core.Constants.Identity
{
    public class ClaimType
    {
        /// <summary>The access token claim type.</summary>
        public const string AccessToken = "urn:oauth:accesstoken";

        /// <summary>The refresh token claim type.</summary>
        public const string RefreshToken = "urn:oauth:refreshtoken";

        /// <summary>The scope claim type.</summary>
        public const string Scope = "urn:oauth:scope";

        /// <summary>The client claim type.</summary>
        public const string Client = "urn:oauth:client";

        /// <summary>The grant type claim type.</summary>
        public const string GrantType = "urn:oauth:granttype";

        /// <summary>The redirect uri claim type.</summary>
        public const string RedirectUri = "urn:oauth:redirecturi";
    }
}