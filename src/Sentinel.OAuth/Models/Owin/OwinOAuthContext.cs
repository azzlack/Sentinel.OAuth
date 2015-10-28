namespace Sentinel.OAuth.Models.Owin
{
    using Microsoft.Owin;
    using System.Collections.Generic;
    using System.Linq;

    public class OwinOAuthContext
    {
        /// <summary>The context.</summary>
        private readonly IOwinContext context;

        /// <summary>
        ///     Initializes a new instance of the Sentinel.OAuth.Extensions.OwinOAuthContext class.
        /// </summary>
        public OwinOAuthContext(IOwinContext context)
        {
            this.context = context;
        }

        /// <summary>Gets or sets the grant_type.</summary>
        /// <value>The grant_type.</value>
        public string GrantType
        {
            get
            {
                return this.context.Get<string>("oauth.GrantType");
            }

            set
            {
                this.context.Set("oauth.GrantType", value);
            }
        }

        /// <summary>Gets or sets the client identifier.</summary>
        /// <value>The client identifier.</value>
        public string ClientId
        {
            get
            {
                return this.context.Get<string>("oauth.ClientId");
            }

            set
            {
                this.context.Set("oauth.ClientId", value);
            }
        }

        /// <summary>Gets or sets the redirect URI.</summary>
        /// <value>The redirect URI.</value>
        public string RedirectUri
        {
            get
            {
                return this.context.Get<string>("oauth.RedirectUri");
            }

            set
            {
                this.context.Set("oauth.RedirectUri", value);
            }
        }

        /// <summary>Gets or sets the scope.</summary>
        /// <value>The scope.</value>
        public IEnumerable<string> Scope
        {
            get
            {
                return this.context.Get<IEnumerable<string>>("oauth.Scope") ?? Enumerable.Empty<string>();
            }

            set
            {
                this.context.Set("oauth.Scope", value);
            }
        }

        /// <summary>Gets or sets the identifier token.</summary>
        /// <value>The identifier token.</value>
        public string IdToken
        {
            get
            {
                return this.context.Get<string>("openid.IdToken");
            }

            set
            {
                this.context.Set("openid.IdToken", value);
            }
        }
    }
}