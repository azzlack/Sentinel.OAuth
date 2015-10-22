namespace Sentinel.Sample.Controllers
{
    using Sentinel.OAuth.Core.Interfaces.Identity;
    using Sentinel.OAuth.Models.Identity;
    using System.Net;
    using System.Net.Http;
    using System.Threading.Tasks;
    using System.Web.Http;
    using System.Web.Http.Description;

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