namespace Sentinel.OAuth.Core.Models.Tokens
{
    public class JsonWebTokenHeader : JsonWebTokenComponent
    {
        /// <summary>Gets the algorithm.</summary>
        /// <value>The algorithm.</value>
        public string Algorithm => this["alg"];

        /// <summary>The type.</summary>
        public string Type => this["typ"];
    }
}