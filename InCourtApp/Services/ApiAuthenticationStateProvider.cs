using Microsoft.AspNetCore.Components.Authorization;
using System.Security.Claims;
using System.Threading.Tasks;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Collections.Generic;

namespace InCourtApp.Services
{
    public class ApiAuthenticationStateProvider : AuthenticationStateProvider
    {
        private readonly ClaimsPrincipal _anonymous = new ClaimsPrincipal(new ClaimsIdentity());

        public override async Task<AuthenticationState> GetAuthenticationStateAsync()
        {
            var token = GetToken();
            if (string.IsNullOrWhiteSpace(token))
            {
                return new AuthenticationState(_anonymous);
            }

            var claims = ParseClaimsFromJwt(token);
            var user = new ClaimsPrincipal(new ClaimsIdentity(claims, "jwt"));
            return new AuthenticationState(user);
        }

        public void MarkUserAsAuthenticated(string token)
        {
            var claims = ParseClaimsFromJwt(token);
            var authenticatedUser = new ClaimsPrincipal(new ClaimsIdentity(claims, "jwt"));
            var authState = Task.FromResult(new AuthenticationState(authenticatedUser));
            NotifyAuthenticationStateChanged(authState);
            SetToken(token);
        }

        public void MarkUserAsLoggedOut()
        {
            var authState = Task.FromResult(new AuthenticationState(_anonymous));
            NotifyAuthenticationStateChanged(authState);
            SetToken(null);
        }

        private IEnumerable<Claim> ParseClaimsFromJwt(string jwt)
        {
            var handler = new JwtSecurityTokenHandler();
            var token = handler.ReadJwtToken(jwt);
            return token.Claims;
        }

        private string _token;
        private string GetToken() => _token;
        private void SetToken(string token) => _token = token;
    }
}
