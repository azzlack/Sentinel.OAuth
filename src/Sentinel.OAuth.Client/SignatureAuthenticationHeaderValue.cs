namespace Sentinel.OAuth.Client
{
    using System;
    using System.Net.Http.Headers;
    using System.Text;

    using Sentinel.OAuth.Core.Extensions;
    using Sentinel.OAuth.Core.Interfaces.Providers;
    using Sentinel.OAuth.Core.Models;

    public class SignatureAuthenticationHeaderValue : AuthenticationHeaderValue
    {
        public SignatureAuthenticationHeaderValue(string userName, string data)
            : base("Signature", EncodeCredential(userName, data))
        {
        }

        public SignatureAuthenticationHeaderValue(SignatureAuthenticationDigest digest)
            : base("Signature", EncodeString(digest.ToString()))
        {
        }

        private static string EncodeCredential(string userName, string data)
        {
            var credential = String.Format("{0}:{1}", userName, data);

            return EncodeString(credential);
        }

        private static string EncodeString(string str)
        {
            var encoding = Encoding.GetEncoding("iso-8859-1");

            return Convert.ToBase64String(encoding.GetBytes(str));
        }
    }
}