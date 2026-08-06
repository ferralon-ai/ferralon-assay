using Microsoft.AspNetCore.Mvc;

namespace Acme.Web
{
    [ApiController]
    [Route("api/[controller]")]
    public class FetchController : ControllerBase
    {
        [HttpGet]
        public string Handle(string target)
        {
            return Fetch(target);
        }

        private string Fetch(string target)
        {
            return OpenConn(target);
        }

        private string OpenConn(string url)
        {
            return url;
        }
    }
}
