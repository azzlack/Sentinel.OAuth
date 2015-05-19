namespace Sentinel.OAuth.Core.Models.OAuth.Http
{
    using System.Diagnostics;

    using Newtonsoft.Json;

    /// <summary>
    /// Represents an OAuth authorization response
    /// </summary>
    [DebuggerDisplay("code: {Code}, state: {State}")]
    public class AuthorizationResponse
    {
        /// <summary>
        /// Gets or sets the code.
        /// </summary>
        /// <value>The code.</value>
        [JsonProperty("code")]
        public string Code { get; set; }

        /// <summary>
        /// Gets or sets the state.
        /// </summary>
        /// <value>The state.</value>
        [JsonProperty("state", NullValueHandling = NullValueHandling.Ignore)]
        public string State { get; set; }
    }
}