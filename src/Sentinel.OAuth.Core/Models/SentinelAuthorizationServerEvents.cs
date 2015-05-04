namespace Sentinel.OAuth.Core.Models
{
    using System;
    using System.Security.Principal;

    using Microsoft.Owin.Security.OAuth;

    public class SentinelAuthorizationServerEvents
    {
        /// <summary>
        ///     Activated when the token has been issued.
        ///     Use this event to do any special handling after the user has authenticated.
        /// </summary>
        /// <example>Set an authentication cookie to log in with token and cookie at the same time.</example>
        public EventHandler<OAuthTokenEndpointResponseContext> TokenIssued;

        /// <summary>
        ///     Activated when the user is logged in and the principal is created.
        ///     Use this event to add any custom claims to the user before the token is created.
        /// </summary>
        public EventHandler<PrincipalCreatedEventArgs> PrincipalCreated;
    }

    public class PrincipalCreatedEventArgs : EventArgs
    {
        /// <summary>
        ///     Initializes a new instance of the Sentinel.OAuth.Core.Models.PrincipalCreatedEventArgs
        ///     class.
        /// </summary>
        /// <param name="principal">The principal.</param>
        /// <param name="context">The context.</param>
        public PrincipalCreatedEventArgs(IPrincipal principal, BaseValidatingContext<OAuthAuthorizationServerOptions> context)
        {
            this.Principal = principal;
            this.Context = context;
        }

        /// <summary>Gets the principal.</summary>
        /// <value>The principal.</value>
        public IPrincipal Principal { get; private set; }

        /// <summary>Gets the context.</summary>
        /// <value>The context.</value>
        public BaseValidatingContext<OAuthAuthorizationServerOptions> Context { get; private set; }
    }
}