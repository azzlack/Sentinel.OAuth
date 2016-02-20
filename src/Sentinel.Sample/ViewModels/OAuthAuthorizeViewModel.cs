namespace Sentinel.Sample.ViewModels
{
    using System.Web.Mvc;

    using Sentinel.Sample.ModelBinders;

    [ModelBinder(typeof(AliasModelBinder))]
    public class OAuthAuthorizeViewModel
    {
        [BindAlias("client_id")]
        public string ClientId { get; set; }

        [BindAlias("redirect_uri")]
        public string RedirectUri { get; set; }

        [BindAlias("scope")]
        public string Scope { get; set; }

        [BindAlias("state")]
        public string State { get; set; }
        
        public bool Grant { get; set; }
    }
}