namespace Sentinel.OAuth.Core.Models
{
    using System;
    using System.Security.Principal;
    using System.Threading.Tasks;

    public class SentinelAuthorizationServerEvents
    {
        /// <summary>
        /// Activated when the token has been issued.
        /// Use this event to do any special handling after the user has authenticated.
        /// </summary>
        /// <example>Set an authentication cookie to log in with token and cookie at the same time.</example>
        public Func<TokenIssuedEventArgs, Task> TokenIssued;

        /// <summary>
        /// Activated when the user is logged in and the principal is created. Use this event to add any
        /// custom claims to the user before the token is created.
        /// </summary>
        public Func<PrincipalCreatedEventArgs, Task> PrincipalCreated;

        /// <summary>
        /// Activated when the token endpoint receives a request for authorization with a non-standard grant_type.
        /// </summary>
        /// <example>Handle application password grant types for applications that doesnt have a GUI.</example>
        public Func<UnknownGrantTypeReceivedEventArgs, Task> UnknownGrantTypeReceived;
    }

    public class UnknownGrantTypeReceivedEventArgs : EventArgs
    {
        /// <summary>
        /// Initializes a new instance of the UnknownGrantTypeReceivedEventArgs class.
        /// </summary>
        /// <param name="context">The OAuth context, <see cref="Microsoft.Owin.Security.OAuth.OAuthGrantCustomExtensionContext"/>.</param>
        public UnknownGrantTypeReceivedEventArgs(object context)
        {
            this.Context = context;
        }

        /// <summary>Gets the OAuth context.</summary>
        /// <remarks><see cref="Microsoft.Owin.Security.OAuth.OAuthGrantCustomExtensionContext"/></remarks>
        /// <value>The OAuth context.</value>
        public object Context { get; private set; }
    }

    public class TokenIssuedEventArgs : EventArgs
    {
        /// <summary>
        /// Initializes a new instance of the TokenIssuedEventArgs class.
        /// </summary>
        /// <param name="context">The OAuth context, <see cref="Microsoft.Owin.Security.OAuth.OAuthTokenEndpointResponseContext"/>.</param>
        public TokenIssuedEventArgs(object context)
        {
            this.Context = context;
        }

        /// <summary>Gets the OAuth context.</summary>
        /// <remarks><see cref="Microsoft.Owin.Security.OAuth.OAuthTokenEndpointResponseContext"/></remarks>
        /// <value>The OAuth context.</value>
        public object Context { get; private set; }
    }

    public class PrincipalCreatedEventArgs : EventArgs
    {
        /// <summary>
        /// Initializes a new instance of the PrincipalCreatedEventArgs class.
        /// </summary>
        /// <param name="principal">The principal.</param>
        /// <param name="context">The OAuth context, <see cref="Microsoft.Owin.Security.OAuth.OAuthGrantResourceOwnerCredentialsContext"/></param>
        public PrincipalCreatedEventArgs(IPrincipal principal, object context)
        {
            this.Principal = principal;
            this.Context = context;
        }

        /// <summary>Gets the principal.</summary>
        /// <value>The principal.</value>
        public IPrincipal Principal { get; set; }

        /// <summary>Gets the OAuth context.</summary>
        /// <remarks><see cref="Microsoft.Owin.Security.OAuth.OAuthGrantResourceOwnerCredentialsContext"/></remarks>
        /// <value>The OAuth context.</value>
        public object Context { get; private set; }
    }
}