namespace Sentinel.OAuth.Client.Mvc5.Models
{
    using System.Web.Mvc;

    using Sentinel.OAuth.Client.Mvc5.Framework.Mvc;

    [ModelBinder(typeof(AliasModelBinder))]
    public class AuthorizeViewModel
    {
        [BindAlias("client_id")]
        public string ClientId { get; set; }

        public string ClientName { get; set; }

        public string ClientDescription { get; set; }

        public string ClientIconUrl { get; set; }

        [BindAlias("redirect_uri")]
        public string RedirectUri { get; set; }

        public string Scope { get; set; }

        public string GrantedScope { get; set; }

        public string State { get; set; }

        [BindAlias("response_type")]
        public string ResponseType { get; set; }

        public bool Grant { get; set; }
    }
}