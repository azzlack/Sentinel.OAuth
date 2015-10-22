namespace Sentinel.OAuth.Core.Constants.Identity
{
    public static class AuthenticationMethod
    {
        /// <summary>Authenticated using client id and client secret.</summary>
        public const string ClientCredentials = "client_credentials";

        /// <summary>Authenticated using client id only.</summary>
        public const string ClientId = "client_id";

        /// <summary>Authenticated using username and password.</summary>
        public const string UserCredentials = "user_credentials";

        /// <summary>Authenticated using user id only.</summary>
        public const string UserId = "user_id";
    }
}