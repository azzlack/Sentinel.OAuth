namespace Sentinel.OAuth.Client.Mvc5
{
    public class CookieConfiguration
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="CookieConfiguration" /> class.
        /// </summary>
        public CookieConfiguration()
        {
            this.AutomaticAuthentication = true;
            this.SaveTokens = true;
        }

        /// <summary>Gets or sets the cookie name.</summary>
        /// <value>The cookie name.</value>
        public string Name { get; set; }

        /// <summary>Gets or sets the domain.</summary>
        /// <value>The domain.</value>
        public string Domain { get; set; }

        /// <summary>Gets or sets a value indicating whether the tokens should be saved as cookies.</summary>
        /// <value>true if save tokens, false if not.</value>
        public bool SaveTokens { get; set; }

        /// <summary>Gets or sets a value indicating whether authentication should automatically be handled.</summary>
        /// <value>true if authentication should automatically be handled, false if not.</value>
        public bool AutomaticAuthentication { get; set; }
    }
}