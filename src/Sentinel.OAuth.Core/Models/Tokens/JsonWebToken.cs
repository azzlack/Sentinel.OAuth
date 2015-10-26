namespace Sentinel.OAuth.Core.Models.Tokens
{
    using Newtonsoft.Json;
    using System;
    using System.Text;

    public class JsonWebToken
    {
        /// <summary>Initializes a new instance of the <see cref="JsonWebToken" /> class.</summary>
        /// <param name="jwt">The jwt.</param>
        public JsonWebToken(string jwt)
        {
            this.Raw = jwt;

            var parts = jwt.Split('.');

            if (parts.Length != 3)
            {
                throw new ArgumentException("Token must consist from 3 delimited by dot parts");
            }

            try
            {
                var header = this.DecodePart(parts[0]);
                var payload = this.DecodePart(parts[1]);
                var signature = this.DecodePart(parts[2]);

                this.Header = JsonConvert.DeserializeObject<JsonWebTokenHeader>(header);
                this.Payload = JsonConvert.DeserializeObject<JsonWebTokenPayload>(payload);
                this.Signature = signature;
            }
            catch (Exception ex)
            {
                throw new ArgumentException("Unable to parse token", ex);
            }
        }

        /// <summary>Gets the raw.</summary>
        /// <value>The raw.</value>
        public string Raw { get; }

        /// <summary>Gets the header.</summary>
        /// <value>The header.</value>
        public JsonWebTokenHeader Header { get; }

        /// <summary>Gets the payload.</summary>
        /// <value>The payload.</value>
        public JsonWebTokenPayload Payload { get; }

        /// <summary>Gets the signature.</summary>
        /// <value>The signature.</value>
        public string Signature { get; }

        /// <summary>Decodes the specified part.</summary>
        /// <param name="part">The part.</param>
        /// <returns>A string.</returns>
        private string DecodePart(string part)
        {
            var cleanPart = part;
            cleanPart = cleanPart.Replace('-', '+'); // 62nd char of encoding
            cleanPart = cleanPart.Replace('_', '/'); // 63rd char of encoding

            // Pad with trailing '='s
            switch (cleanPart.Length % 4)
            {
                case 0:
                    break; // No pad chars in this case
                case 2:
                    cleanPart += "==";
                    break; // Two pad chars
                case 3:
                    cleanPart += "=";
                    break; // One pad char
                default:
                    throw new ArgumentException("Illegal base64url string");
            }

            var converted = Convert.FromBase64String(cleanPart); // Standard base64 decoder

            return Encoding.UTF8.GetString(converted, 0, converted.Length);
        }
    }
}