namespace Sentinel.Sample.Controllers
{
    using System.Linq;
    using System.Net;
    using System.Net.Http;
    using System.Security.Claims;
    using System.Threading.Tasks;
    using System.Web.Http;
    using System.Web.Http.Description;

    using Sentinel.OAuth.Core.Models.Identity;

    [Authorize]
    public class IdentityController : ApiController
    {
        /// <summary>
        /// Gets the logged-in users claims.
        /// </summary>
        /// <returns>A list of claims.</returns>
        [Route("api/identity")]
        [ResponseType(typeof(JsonIdentity))]
        public async Task<HttpResponseMessage> Get()
        {
            if (ClaimsPrincipal.Current != null)
            {
                return this.Request.CreateResponse(HttpStatusCode.OK, new JsonIdentity(ClaimsPrincipal.Current.Identities.First()));
            }

            return this.Request.CreateErrorResponse(HttpStatusCode.InternalServerError, "Error when retrieving current user identity");
        }
    }
}