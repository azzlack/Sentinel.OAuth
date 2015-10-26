namespace Sentinel.OAuth.Client.Helpers
{
    using System;
    using System.Collections.Generic;

    public class JwtHelper
    {
        public static IEnumerable<KeyValuePair<string, string>> DecodeHeader(string token)
        {
            throw new NotImplementedException();
        }

        public static IEnumerable<KeyValuePair<string, string>> DecodePayload(string token)
        {
            throw new NotImplementedException();
        }

        public static bool Verify(string accessToken, string idToken)
        {
            throw new NotImplementedException();
        }
    }
}