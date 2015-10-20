namespace Sentinel.OAuth.TokenManagers.RedisTokenRepository.Models
{
    using Newtonsoft.Json;
    using Sentinel.OAuth.Core.Interfaces.Models;
    using Sentinel.OAuth.Core.Models.OAuth;
    using StackExchange.Redis;
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;

    public class RedisAuthorizationCode : AuthorizationCode
    {
        /// <summary>The identifier.</summary>
        private RedisTokenIdentifier id;

        /// <summary>
        /// Initializes a new instance of the
        /// Sentinel.OAuth.TokenManagers.RedisTokenRepository.Models.RedisAuthorizationCode class.
        /// </summary>
        public RedisAuthorizationCode()
        {
        }

        public RedisAuthorizationCode(IAuthorizationCode authorizationCode)
            : base(authorizationCode)
        {
            this.id = this.GenerateIdentity(authorizationCode.ClientId, authorizationCode.RedirectUri, authorizationCode.Subject, authorizationCode.ValidTo);

            this.Created = DateTime.UtcNow;
        }

        /// <summary>
        /// Initializes a new instance of the
        /// Sentinel.OAuth.TokenManagers.RedisTokenRepository.Models.RedisAuthorizationCode class.
        /// </summary>
        /// <param name="hashEntries">The hash entries.</param>
        public RedisAuthorizationCode(HashEntry[] hashEntries)
        {
            var clientId = hashEntries.FirstOrDefault(x => x.Name == "ClientId");
            var redirectUri = hashEntries.FirstOrDefault(x => x.Name == "RedirectUri");
            var subject = hashEntries.FirstOrDefault(x => x.Name == "Subject");
            var code = hashEntries.FirstOrDefault(x => x.Name == "Code");
            var ticket = hashEntries.FirstOrDefault(x => x.Name == "Ticket");
            var validTo = hashEntries.FirstOrDefault(x => x.Name == "ValidTo");
            var created = hashEntries.FirstOrDefault(x => x.Name == "Created");

            this.ClientId = clientId.Value.HasValue ? clientId.Value.ToString() : string.Empty;
            this.RedirectUri = redirectUri.Value.HasValue ? redirectUri.Value.ToString() : string.Empty;
            this.Subject = subject.Value.HasValue ? subject.Value.ToString() : string.Empty;
            this.Code = code.Value.HasValue ? code.Value.ToString() : string.Empty;
            this.Ticket = ticket.Value.HasValue ? ticket.Value.ToString() : string.Empty;
            this.ValidTo = validTo.Value.HasValue ? JsonConvert.DeserializeObject<DateTime>(validTo.Value.ToString()) : DateTime.MinValue;
            this.Created = created.Value.HasValue ? JsonConvert.DeserializeObject<DateTime>(created.Value.ToString()) : DateTime.MinValue;

            this.id = this.GenerateIdentity(this.ClientId, this.RedirectUri, this.Subject, this.ValidTo);
        }

        /// <summary>
        /// Gets or sets the created date.
        /// </summary>
        /// <value>The created date.</value>
        public DateTime Created { get; set; }

        /// <summary>Gets the identifier.</summary>
        /// <returns>The identifier.</returns>
        public override object GetIdentifier()
        {
            return this.id ?? (this.id = this.GenerateIdentity(this.ClientId, this.RedirectUri, this.Subject, this.ValidTo));
        }

        /// <summary>Check if this object is valid.</summary>
        /// <returns><c>true</c> if valid, <c>false</c> if not.</returns>
        public override bool IsValid()
        {
            return base.IsValid() && this.Created != DateTime.MinValue;
        }

        /// <summary>Tests if this IAuthorizationCode is considered equal to another.</summary>
        /// <param name="other">The code to compare to this object.</param>
        /// <returns>true if the objects are considered equal, false if they are not.</returns>
        public override bool Equals(IAuthorizationCode other)
        {
            var id1 = this.GetIdentifier();
            var id2 = other.GetIdentifier();

            if (id1 is IEquatable<RedisTokenIdentifier> && id2 is IEquatable<RedisTokenIdentifier>)
            {
                return id1.Equals(id2);
            }

            return base.Equals(other);
        }

        /// <summary>Converts this object to a list of hash entries.</summary>
        /// <returns>This object as a Redis hash.</returns>
        public HashEntry[] ToHashEntries()
        {
            var entries = new List<HashEntry>();

            entries.Add(new HashEntry("ClientId", this.ClientId));
            entries.Add(new HashEntry("RedirectUri", this.RedirectUri ?? string.Empty));
            entries.Add(new HashEntry("Subject", this.Subject));
            entries.Add(new HashEntry("Code", this.Code));
            entries.Add(new HashEntry("Scope", JsonConvert.SerializeObject(this.Scope ?? new string[0])));
            entries.Add(new HashEntry("Ticket", this.Ticket));
            entries.Add(new HashEntry("ValidTo", JsonConvert.SerializeObject(this.ValidTo)));
            entries.Add(new HashEntry("Created", JsonConvert.SerializeObject(this.Created)));

            return entries.ToArray();
        }

        /// <summary>Generates an identity.</summary>
        /// <param name="clientId">The client id.</param>
        /// <param name="redirectUri">The redirect uri.</param>
        /// <param name="subject">The subject.</param>
        /// <param name="validTo">The valid to Date/Time.</param>
        /// <returns>The identity.</returns>
        private RedisTokenIdentifier GenerateIdentity(string clientId, string redirectUri, string subject, DateTime validTo)
        {
            return
                new RedisTokenIdentifier(
                    Convert.ToBase64String(Encoding.UTF8.GetBytes(clientId + redirectUri + subject + validTo.Ticks)),
                    clientId,
                    redirectUri,
                    subject);
        }
    }
}