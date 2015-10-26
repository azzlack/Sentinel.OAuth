namespace Sentinel.OAuth.Core.Extensions
{
    using System;

    public static class DateTimeOffsetExtensions
    {
        /// <summary>The epoch.</summary>
        public static readonly DateTimeOffset Epoch = new DateTimeOffset(1970, 1, 1, 0, 0, 0, 0, TimeSpan.Zero);

        /// <summary>A DateTime extension method that converts a DateTime to an unix time.</summary>
        /// <param name="dateTime">The DateTime to act on.</param>
        /// <returns>The date/time as seconds since epoch.</returns>
        public static long ToUnixTime(this DateTimeOffset dateTime)
        {
            return Convert.ToInt64(dateTime.Subtract(Epoch).TotalSeconds);
        }

        /// <summary>
        /// An extension method that converts a unix time to a DateTime.
        /// </summary>
        /// <param name="unixTime">The unix time to act on.</param>
        /// <returns>A DateTime in UTC.</returns>
        public static DateTimeOffset ToDateTimeOffset(this long unixTime)
        {
            return Epoch.AddSeconds(unixTime);
        }
    }
}