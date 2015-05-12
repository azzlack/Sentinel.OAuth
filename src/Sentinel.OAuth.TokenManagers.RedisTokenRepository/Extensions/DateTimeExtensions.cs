namespace Sentinel.OAuth.TokenManagers.RedisTokenRepository.Extensions
{
    using System;

    public static class DateTimeExtensions
    {
        /// <summary>A DateTime extension method that converts a dateTime to an unix time.</summary>
        /// <param name="dateTime">The DateTime to act on.</param>
        /// <returns>The datetime as seconds since epoch.</returns>
        public static double ToUnixTime(this DateTime dateTime)
        {
            var epoch = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);

            return dateTime.Subtract(epoch).TotalSeconds;
        }
    }
}