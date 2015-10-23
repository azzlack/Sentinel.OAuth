namespace Sentinel.OAuth.Core.Models.OAuth.Http
{
    using Newtonsoft.Json;
    using System.Diagnostics;

    /// <summary>
    /// Represents an OAuth error response
    /// </summary>
    [DebuggerDisplay("error: {ErrorCode}, error_description: {ErrorDescription}, error_uri: {ErrorUri}")]
    public class ErrorResponse
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="ErrorResponse"/> class.
        /// </summary>
        public ErrorResponse()
        {
            this.ErrorCode = "invalid_client";
        }

        /// <summary>Initializes a new instance of the <see cref="ErrorResponse" /> class.</summary>
        /// <param name="errorCode">The error code.</param>
        public ErrorResponse(string errorCode)
        {
            this.ErrorCode = errorCode;
        }

        /// <summary>
        /// Gets or sets the error code.
        /// </summary>
        /// <value>The error code.</value>
        [JsonProperty("error")]
        public string ErrorCode { get; set; }

        /// <summary>
        /// Gets or sets a human-readable ASCII [USASCII] text providing additional information, 
        /// used to assist the client developer in understanding the error that occurred.
        /// </summary>
        /// <remarks>
        /// The value MUST NOT include characters outside the set %x20-21 / %x23-5B / %x5D-7E.
        /// </remarks>
        /// <value>The error description.</value>
        [JsonProperty("error_description", NullValueHandling = NullValueHandling.Ignore)]
        public string ErrorDescription { get; set; }

        /// <summary>
        /// Gets or sets a URI identifying a human-readable web page with information about the error, 
        /// used to provide the client developer with additional information about the error.
        /// </summary>
        /// <remarks>
        /// The value MUST conform to the URI-reference syntax and thus MUST NOT include characters outside the set %x21 / %x23-5B / %x5D-7E.
        /// </remarks>
        /// <value>The error URI.</value>
        [JsonProperty("error_uri", NullValueHandling = NullValueHandling.Ignore)]
        public string ErrorUri { get; set; }
    }
}