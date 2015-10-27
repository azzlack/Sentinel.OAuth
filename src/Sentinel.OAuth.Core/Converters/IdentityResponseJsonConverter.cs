namespace Sentinel.OAuth.Core.Converters
{
    using Newtonsoft.Json;
    using Sentinel.OAuth.Core.Models.OAuth.Http;
    using System;
    using System.Collections.Generic;
    using System.Reflection;

    public class IdentityResponseJsonConverter : JsonConverter
    {
        /// <summary>
        /// Writes the JSON representation of the object.
        /// </summary>
        /// <param name="writer">The <see cref="T:Newtonsoft.Json.JsonWriter"/> to write to.</param><param name="value">The value.</param><param name="serializer">The calling serializer.</param>
        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
        {
            var obj = value as IdentityResponse;

            if (obj == null)
            {
                writer.WriteNull();
                return;
            }

            writer.WriteStartObject();

            foreach (var claim in obj)
            {
                writer.WritePropertyName(claim.Key);
                writer.WriteValue(claim.Value);
            }

            writer.WriteEndObject();
        }

        /// <summary>
        /// Reads the JSON representation of the object.
        /// </summary>
        /// <param name="reader">The <see cref="T:Newtonsoft.Json.JsonReader"/> to read from.</param><param name="objectType">Type of the object.</param><param name="existingValue">The existing value of object being read.</param><param name="serializer">The calling serializer.</param>
        /// <returns>
        /// The object value.
        /// </returns>
        public override object ReadJson(
            JsonReader reader,
            Type objectType,
            object existingValue,
            JsonSerializer serializer)
        {
            if (reader.TokenType == JsonToken.Null)
            {
                return null;
            }

            var claims = new List<KeyValuePair<string, string>>();

            while (reader.Read())
            {
                if (reader.TokenType == JsonToken.PropertyName)
                {
                    var propertyName = reader.Value.ToString();

                    if (!reader.Read())
                    {
                        throw new JsonSerializationException("Unexpected end when reading IdentityResponse.");
                    }

                    // Skip until all comments are gone
                    while (reader.TokenType == JsonToken.Comment)
                    {
                        if (!reader.Read())
                        {
                            throw new JsonSerializationException("Unexpected end when reading IdentityResponse.");
                        }
                    }

                    switch (reader.TokenType)
                    {
                        default:
                            if (this.IsPrimitiveToken(reader.TokenType))
                            {
                                claims.Add(new KeyValuePair<string, string>(propertyName, reader.Value.ToString()));
                                break;
                            }

                            throw new JsonSerializationException($"Unexpected token when reading value for {propertyName}: {reader.Value} ({reader.TokenType})");
                    }
                }
            }

            return new IdentityResponse(claims);
        }

        /// <summary>
        /// Determines whether this instance can convert the specified object type.
        /// </summary>
        /// <param name="objectType">Type of the object.</param>
        /// <returns>
        /// <c>true</c> if this instance can convert the specified object type; otherwise, <c>false</c>.
        /// </returns>
        public override bool CanConvert(Type objectType)
        {
            return typeof(IdentityResponse).GetTypeInfo().IsAssignableFrom(objectType.GetTypeInfo());
        }

        /// <summary>Query if 'token' is primitive token.</summary>
        /// <param name="token">The token.</param>
        /// <returns>true if primitive token, false if not.</returns>
        internal bool IsPrimitiveToken(JsonToken token)
        {
            switch (token)
            {
                case JsonToken.Integer:
                case JsonToken.Float:
                case JsonToken.String:
                case JsonToken.Boolean:
                case JsonToken.Undefined:
                case JsonToken.Null:
                case JsonToken.Date:
                case JsonToken.Bytes:
                    return true;
                default:
                    return false;
            }
        }
    }
}