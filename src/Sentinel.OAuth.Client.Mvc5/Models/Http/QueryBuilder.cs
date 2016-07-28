namespace Sentinel.OAuth.Client.Mvc5.Models.Http
{
    using System;
    using System.Collections;
    using System.Collections.Generic;
    using System.Text;

    using Microsoft.Owin;

    public class QueryBuilder : IEnumerable<KeyValuePair<string, string>>
    {
        private IList<KeyValuePair<string, string>> parameters;

        public QueryBuilder()
        {
            this.parameters = new List<KeyValuePair<string, string>>();
        }

        public QueryBuilder(IEnumerable<KeyValuePair<string, string>> parameters)
        {
            this.parameters = new List<KeyValuePair<string, string>>(parameters);
        }

        public void Add(string key, IEnumerable<string> values)
        {
            foreach (var value in values)
            {
                this.parameters.Add(new KeyValuePair<string, string>(key, value));
            }
        }

        public void Add(string key, string value)
        {
            this.parameters.Add(new KeyValuePair<string, string>(key, value));
        }

        public override string ToString()
        {
            var builder = new StringBuilder();
            bool first = true;
            for (int i = 0; i < this.parameters.Count; i++)
            {
                var pair = this.parameters[i];
                builder.Append(first ? "?" : "&");
                first = false;
                builder.Append(Uri.EscapeDataString(pair.Key));
                builder.Append("=");
                builder.Append(Uri.EscapeDataString(pair.Value));
            }

            return builder.ToString();
        }

        public QueryString ToQueryString()
        {
            return new QueryString(this.ToString());
        }

        public override int GetHashCode()
        {
            return this.ToQueryString().GetHashCode();
        }

        public override bool Equals(object obj)
        {
            return this.ToQueryString().Equals(obj);
        }

        public IEnumerator<KeyValuePair<string, string>> GetEnumerator()
        {
            return this.parameters.GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return this.parameters.GetEnumerator();
        }
    }
}