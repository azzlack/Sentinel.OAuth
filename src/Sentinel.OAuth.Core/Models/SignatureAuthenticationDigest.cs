namespace Sentinel.OAuth.Core.Models
{
    using System;

    public class SignatureAuthenticationDigest
    {
        /// <summary>Initializes a new instance of the <see cref="SignatureAuthenticationDigest" /> class.</summary>
        /// <param name="userId">The identifier of the user.</param>
        /// <param name="clientId">The identifier of the client.</param>
        /// <param name="redirectUri">URI of the redirect.</param>
        /// <param name="requestUrl">URL of the request.</param>
        /// <param name="timestamp">The timestamp in seconds since epoch (UTC).</param>
        /// <param name="nonce">The nonce.</param>
        /// <param name="signature">The signature.</param>
        public SignatureAuthenticationDigest(string userId, string clientId, string redirectUri, string requestUrl, long timestamp, string nonce, string signature = null)
        {
            this.UserId = userId;
            this.ClientId = clientId;
            this.RedirectUri = redirectUri;
            this.RequestUrl = requestUrl;
            this.Timestamp = timestamp;
            this.Nonce = nonce;
            this.Signature = signature;
        }

        /// <summary>Gets the identifier of the user.</summary>
        /// <value>The identifier of the user.</value>
        public string UserId { get; }

        /// <summary>Gets the identifier of the client.</summary>
        /// <value>The identifier of the client.</value>
        public string ClientId { get; }

        /// <summary>Gets the redirect uri for the client.</summary>
        /// <value>The redirect uri for the client.</value>
        public string RedirectUri { get; }

        /// <summary>Gets URL of the request.</summary>
        /// <value>The request URL.</value>
        public string RequestUrl { get; }

        /// <summary>Gets the nonce.</summary>
        /// <value>The nonce.</value>
        public string Nonce { get; }

        /// <summary>Gets or sets the timestamp in seconds since epoch (UTC).</summary>
        /// <value>The timestamp in seconds since epoch (UTC).</value>
        public long Timestamp { get; set; }

        /// <summary>Gets the signature.</summary>
        /// <value>The signature.</value>
        public string Signature { get; private set; }

        /// <summary>Gets the data.</summary>
        /// <returns>The data.</returns>
        public string GetData()
        {
            return $"user_id={this.UserId},client_id={this.ClientId},redirect_uri={this.RedirectUri},request_url={this.RequestUrl},timestamp={this.Timestamp},nonce={this.Nonce}";
        }

        /// <summary>Sets the signature.</summary>
        /// <param name="signature">The signature.</param>
        public void Sign(string signature)
        {
            this.Signature = signature;
        }

        /// <summary>Returns a string that represents the current object.</summary>
        /// <returns>A string that represents the current object.</returns>
        public override string ToString()
        {
            return $"{this.GetData()},signature={this.Signature}";
        }
    }
}