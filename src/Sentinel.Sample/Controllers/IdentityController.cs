namespace Sentinel.Sample.Controllers
{
    using System.Net;
    using System.Net.Http;
    using System.Threading.Tasks;
    using System.Web.Http;
    using System.Web.Http.Description;

    using Sentinel.OAuth.Core.Interfaces.Identity;
    using Sentinel.OAuth.Models.Identity;

    [Authorize]
    public class IdentityController : ApiController
    {
        /// <summary>
        /// Gets the logged-in users claims.
        /// </summary>
        /// <returns>A list of claims.</returns>
        [Route("api/identity")]
        [ResponseType(typeof(ISentinelIdentity))]
        public async Task<HttpResponseMessage> Get()
        {
            if (SentinelPrincipal.Current != null)
            {
                return this.Request.CreateResponse(HttpStatusCode.OK, SentinelPrincipal.Current.Identity);
            }

            return this.Request.CreateErrorResponse(HttpStatusCode.InternalServerError, "Error when retrieving current user identity");
        }
    }
}