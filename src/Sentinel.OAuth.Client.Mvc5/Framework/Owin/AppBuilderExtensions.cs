namespace Sentinel.OAuth.Client.Mvc5.Framework.Owin
{
    using System;

    using global::Owin;

    using Microsoft.AspNet.Identity;
    using Microsoft.Owin.Security.Cookies;

    using Constants = Sentinel.OAuth.Client.Models.Constants;

    public static class AppBuilderExtensions
    {
        public static IAppBuilder UseSentinelAuthentication(this IAppBuilder app, Func<SentinelAuthenticationOptions> optionsBuilder)
        {
            if (app == null)
            {
                throw new ArgumentNullException(nameof(app));
            }

            if (optionsBuilder == null)
            {
                throw new ArgumentNullException(nameof(optionsBuilder));
            }

            var options = optionsBuilder();

            // Set up cookie authentication if specified
            if (options.CookieConfiguration.AutomaticAuthentication)
            {
                app.UseCookieAuthentication(
                    new CookieAuthenticationOptions()
                        {
                            AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie,
                            CookieName = options.CookieConfiguration.Name,
                            CookieDomain = options.CookieConfiguration.Domain
                        });
            }
            
            app.Use(typeof(SentinelAuthenticationMiddleware), app, options);

            // Set up static paths
            app.Map(
                options.Endpoints.LoginEndpointUrl.StartsWith("/") ? options.Endpoints.LoginEndpointUrl : $"/{options.Endpoints.LoginEndpointUrl}",
                builder =>
                    {
                        builder.Run(
                            async context =>
                                {
                                    await options.Events.OnSignIn(context, options);
                                });
                    });

            app.Map(
                options.Endpoints.LogoutEndpointUrl.StartsWith("/") ? options.Endpoints.LogoutEndpointUrl : $"/{options.Endpoints.LogoutEndpointUrl}",
                builder =>
                    {
                        builder.Run(
                            async context =>
                                {
                                    await options.Events.OnSignOut(context, options);
                                });
                    });

            app.Map(
                options.Endpoints.RefreshEndpointUrl.StartsWith("/") ? options.Endpoints.RefreshEndpointUrl : $"/{options.Endpoints.RefreshEndpointUrl}",
                builder =>
                    {
                        builder.Run(
                            async context =>
                                {
                                    await options.Events.OnRefresh(context, options);
                                });
                    });

            app.Map(
                options.Endpoints.ErrorEndpointUrl.StartsWith("/") ? options.Endpoints.ErrorEndpointUrl : $"/{options.Endpoints.ErrorEndpointUrl}",
                builder =>
                {
                    builder.Run(
                        async context =>
                        {
                            await options.Events.OnError(context, options);
                        });
                });

            app.MapWhen(
                context =>
                    {
                        // Find out if this is an OAuth authorize request
                        var query = context.Request.Query;
                        if (context.Request.Uri.GetLeftPart(UriPartial.Path) == options.RedirectUri
                            && query["code"] != null && query["state"] != null)
                        {
                            return true;
                        }

                        return false;
                    },
                builder =>
                    {
                        builder.Run(
                            async context =>
                                {
                                    await options.Events.OnAuthorizeCallback(context, options);
                                });
                    });

            return app;
        }

        public static IAppBuilder UseSentinelAuthentication(this IAppBuilder app, string authenticationServerUrl, string clientId, string clientSecret, string redirectUri)
        {
            return UseSentinelAuthentication(
                app,
                () => new SentinelAuthenticationOptions(authenticationServerUrl, clientId, clientSecret, redirectUri));
        }
    }
}