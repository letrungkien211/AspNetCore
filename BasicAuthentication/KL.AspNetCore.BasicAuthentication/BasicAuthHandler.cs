using System.Linq;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace KL.AspNetCore.BasicAuthentication
{
    /// <summary>
    /// Basic authentication handler
    /// </summary>
    public class BasicAuthHandler : AuthenticationHandler<AuthenticationSchemeOptions>
    {
        private IUserManager UserManager { get; }

        /// <summary>
        /// Basic authentication handler
        /// </summary>
        /// <param name="options"></param>
        /// <param name="logger"></param>
        /// <param name="encoder"></param>
        /// <param name="clock"></param>
        /// <param name="userManager">user manager</param>
        public BasicAuthHandler(
            IOptionsMonitor<AuthenticationSchemeOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock,
            IUserManager userManager
            ) : base(options, logger, encoder, clock)
        {
            UserManager = userManager;
        }

        /// <summary>
        /// Handle authentication
        /// </summary>
        /// <returns></returns>
        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (AuthenticationHeaderValue.TryParse(Request.Headers["Authorization"], out var authenticationHeaderValue))
            {
                var (name, pass) = authenticationHeaderValue.Parameter.AuthorizationParameterToBasicAuth();

                if(string.IsNullOrEmpty(name) || string.IsNullOrEmpty(pass))
                {
                    return AuthenticateResult.NoResult();
                }

                var userAuthInfo = await UserManager.Authenticate(name, pass);
                if (userAuthInfo == null)
                    return AuthenticateResult.Fail($"Name={name} is not found.");

                var identity = new ClaimsIdentity(userAuthInfo.Select(x => new Claim(x.Key, x.Value)), BasicAuthenticationConstants.Basic);
                return AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), BasicAuthenticationConstants.Basic));
            }
            return AuthenticateResult.NoResult();
        }
    }
}