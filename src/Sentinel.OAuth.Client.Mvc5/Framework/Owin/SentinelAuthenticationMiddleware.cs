namespace Sentinel.OAuth.Client.Mvc5.Framework.Owin
{
    using System;
    using System.Net.Http;

    using global::Owin;

    using Microsoft.Owin;
    using Microsoft.Owin.Logging;
    using Microsoft.Owin.Security.DataHandler;
    using Microsoft.Owin.Security.DataProtection;
    using Microsoft.Owin.Security.Infrastructure;

    public class SentinelAuthenticationMiddleware : AuthenticationMiddleware<SentinelAuthenticationOptions>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="SentinelAuthenticationMiddleware" /> class.
        /// </summary>
        /// <param name="next">The next.</param>
        /// <param name="app">The application.</param>
        /// <param name="options">Options for controlling the operation.</param>
        public SentinelAuthenticationMiddleware(OwinMiddleware next, IAppBuilder app, SentinelAuthenticationOptions options)
            : base(next, options)
        {
            // Set up defaults
            this.Options.Scope.Add("openid");
            this.Options.Logger = app.CreateLogger<SentinelAuthenticationMiddleware>();

#if DEBUG
            this.Options.BackchannelHttpHandler = this.Options.BackchannelHttpHandler ?? new WebRequestHandler()
                                                      {
                                                          ServerCertificateValidationCallback = (sender, certificate, chain, errors) => true
                                                      };
#endif

            var backchannel = new HttpClient(this.Options.BackchannelHttpHandler ?? new WebRequestHandler())
                                      {
                                          BaseAddress = new Uri(this.Options.AuthenticationServerUrl)
                                      };
            backchannel.DefaultRequestHeaders.UserAgent.ParseAdd("Sentinel OAuth middleware");
            backchannel.MaxResponseContentBufferSize = 1024 * 1024 * 10; // 10 MB
            backchannel.Timeout = TimeSpan.FromSeconds(60);
            this.Options.Backchannel = backchannel;

            if (this.Options.StateDataFormat == null)
            {
                var dataProtector = app.CreateDataProtector(typeof(SentinelAuthenticationMiddleware).FullName, this.Options.AuthenticationType, "v1");
                this.Options.StateDataFormat = new PropertiesDataFormat(dataProtector);
            }
        }

        protected override AuthenticationHandler<SentinelAuthenticationOptions> CreateHandler()
        {
            return new SentinelAuthenticationHandler();
        }
    }
}