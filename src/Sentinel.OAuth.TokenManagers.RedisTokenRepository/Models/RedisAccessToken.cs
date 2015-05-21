namespace Sentinel.OAuth.TokenManagers.RedisTokenRepository.Models
{
    using System;
    using System.Collections.Generic;
    using System.Linq;

    using Newtonsoft.Json;

    using Sentinel.OAuth.Core.Models.OAuth;

    using StackExchange.Redis;

    public class RedisAccessToken : AccessToken
    {
        /// <summary>
        /// Initializes a new instance of the
        /// Sentinel.OAuth.TokenManagers.RedisTokenRepository.Models.RedisAccessToken class.
        /// </summary>
        public RedisAccessToken()
        {
        }

        /// <summary>
        /// Initializes a new instance of the
        /// Sentinel.OAuth.TokenManagers.RedisTokenRepository.Models.RedisAccessToken class.
        /// </summary>
        /// <param name="hashEntries">The hash entries.</param>
        public RedisAccessToken(HashEntry[] hashEntries)
        {
            var clientId = hashEntries.FirstOrDefault(x => x.Name == "ClientId");
            var redirectUri = hashEntries.FirstOrDefault(x => x.Name == "RedirectUri");
            var subject = hashEntries.FirstOrDefault(x => x.Name == "Subject");
            var token = hashEntries.FirstOrDefault(x => x.Name == "Token");
            var ticket = hashEntries.FirstOrDefault(x => x.Name == "Ticket");
            var validTo = hashEntries.FirstOrDefault(x => x.Name == "ValidTo");
            var created = hashEntries.FirstOrDefault(x => x.Name == "Created");

            this.ClientId = clientId.Value.HasValue ? clientId.Value.ToString() : string.Empty;
            this.RedirectUri = redirectUri.Value.HasValue ? redirectUri.Value.ToString() : string.Empty;
            this.Subject = subject.Value.HasValue ? subject.Value.ToString() : string.Empty;
            this.Token = token.Value.HasValue ? token.Value.ToString() : string.Empty;
            this.Ticket = ticket.Value.HasValue ? ticket.Value.ToString() : string.Empty;
            this.ValidTo = validTo.Value.HasValue ? JsonConvert.DeserializeObject<DateTime>(validTo.Value.ToString()) : DateTime.MinValue;
            this.Created = created.Value.HasValue ? JsonConvert.DeserializeObject<DateTime>(created.Value.ToString()) : DateTime.MinValue;
        }

        /// <summary>Gets or sets the identifier.</summary>
        /// <value>The identifier.</value>
        public string Id { get; set; }

        /// <summary>
        /// Gets or sets the created date.
        /// </summary>
        /// <value>The created date.</value>
        public DateTime Created { get; set; }

        /// <summary>Converts this object to a list of hash entries.</summary>
        /// <returns>This object as a Redis hash.</returns>
        public HashEntry[] ToHashEntries()
        {
            var entries = new List<HashEntry>();

            entries.Add(new HashEntry("ClientId", this.ClientId));
            entries.Add(new HashEntry("RedirectUri", this.RedirectUri ?? string.Empty));
            entries.Add(new HashEntry("Subject", this.Subject));
            entries.Add(new HashEntry("Scope", JsonConvert.SerializeObject(this.Scope ?? new string[0])));
            entries.Add(new HashEntry("Token", this.Token));
            entries.Add(new HashEntry("Ticket", this.Ticket));
            entries.Add(new HashEntry("ValidTo", JsonConvert.SerializeObject(this.ValidTo)));
            entries.Add(new HashEntry("Created", JsonConvert.SerializeObject(this.Created)));

            return entries.ToArray();
        }
    }
}