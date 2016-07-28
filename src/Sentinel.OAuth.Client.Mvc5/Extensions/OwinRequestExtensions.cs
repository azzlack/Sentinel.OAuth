﻿namespace Sentinel.OAuth.Client.Mvc5.Extensions
{
    using System;

    using Microsoft.Owin;

    public static class OwinRequestExtensions
    {
        public static bool IsLocalUrl(this IOwinRequest request, string url)
        {
            if (string.IsNullOrEmpty(url))
            {
                return false;
            }

            // If it is an absolute url, validate that the base is the same as the current request
            Uri absoluteUri;
            if (Uri.TryCreate(url, UriKind.Absolute, out absoluteUri))
            {
                var host = new Uri(request.Uri.GetLeftPart(UriPartial.Authority));
                if (host.IsBaseOf(absoluteUri))
                {
                    return true;
                }

                return false;
            }

            // Check if it is a valid relative url
            if (url[0] == 47 && (url.Length == 1 || url[1] != 47 && url[1] != 92))
            {
                return true;
            }

            if (url.Length > 1 && url[0] == 126)
            {
                return url[1] == 47;
            }

            return false;
        }
    }
}