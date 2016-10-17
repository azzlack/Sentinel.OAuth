namespace Sentinel.OAuth.Client
{
    using System;
    using System.Net.Http.Headers;
    using System.Text;
    
    using Sentinel.OAuth.Core.Models;

    public class SignatureAuthenticationHeaderValue : AuthenticationHeaderValue
    {
        public SignatureAuthenticationHeaderValue(SignatureAuthenticationDigest digest)
            : base("Signature", EncodeString(digest.ToString()))
        {
        }

        private static string EncodeString(string str)
        {
            var encoding = Encoding.GetEncoding("iso-8859-1");

            return Convert.ToBase64String(encoding.GetBytes(str));
        }
    }
}