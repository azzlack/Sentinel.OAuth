namespace Sentinel.OAuth.Implementation.Handlers
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.IdentityModel.Tokens;
    using System.Security.Claims;

    public class SentinelJwtSecurityTokenHandler : JwtSecurityTokenHandler
    {
        /// <summary>Creates claims identity.</summary>
        /// <param name="jwt">                 The jwt.</param>
        /// <param name="issuer">              The issuer.</param>
        /// <param name="validationParameters">Options for controlling the validation.</param>
        /// <returns>The new claims identity.</returns>
        protected override ClaimsIdentity CreateClaimsIdentity(JwtSecurityToken jwt, string issuer, TokenValidationParameters validationParameters)
        {
            if (jwt == null)
            {
                throw new ArgumentNullException("jwt");
            }

            if (string.IsNullOrWhiteSpace(issuer))
            {
                throw new ArgumentException("IDX10221: Unable to create claims from securityToken, 'issuer' is null or empty.");
            }

            var claimsIdentity = validationParameters.CreateClaimsIdentity(jwt, issuer);

            foreach (var claim in jwt.Claims)
            {
                if (!JwtSecurityTokenHandler.InboundClaimFilter.Contains(claim.Type))
                {
                    bool flag = true;
                    string type;
                    if (!JwtSecurityTokenHandler.InboundClaimTypeMap.TryGetValue(claim.Type, out type))
                    {
                        type = claim.Type;
                        flag = false;
                    }
                    if (type == "http://schemas.xmlsoap.org/ws/2009/09/identity/claims/actor")
                    {
                        if (claimsIdentity.Actor != null)
                            throw new InvalidOperationException(string.Format((IFormatProvider)CultureInfo.InvariantCulture, "IDX10710: Only a single 'Actor' is supported. Found second claim of type: '{0}', value: '{1}'", new object[2]
                            {
                (object) "actort",
                (object) claim.Value
                            }));
                        if (this.CanReadToken(claim.Value))
                        {
                            JwtSecurityToken jwt1 = this.ReadToken(claim.Value) as JwtSecurityToken;
                            claimsIdentity.Actor = this.CreateClaimsIdentity(jwt1, issuer, validationParameters);
                        }
                    }
                    Claim claim2 = new Claim(type, claim.Value, claim.ValueType, issuer, issuer, claimsIdentity);
                    if (claim.Properties.Count > 0)
                    {
                        foreach (KeyValuePair<string, string> keyValuePair in (IEnumerable<KeyValuePair<string, string>>)claim.Properties)
                            claim2.Properties[keyValuePair.Key] = keyValuePair.Value;
                    }
                    if (flag)
                        claim2.Properties[JwtSecurityTokenHandler.ShortClaimTypeProperty] = claim.Type;
                    claimsIdentity.AddClaim(claim2);
                }
            }
            return claimsIdentity;
        }
    }
}