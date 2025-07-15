using System.Net.Http;
using System.Net.Http.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Components.Authorization;
using System.Security.Claims;

namespace InCourtApp.Services
{
    public class AuthService
    {
        private readonly HttpClient _httpClient;
        private readonly AuthenticationStateProvider _authenticationStateProvider;
        private string _token;

        public AuthService(HttpClient httpClient, AuthenticationStateProvider authenticationStateProvider)
        {
            _httpClient = httpClient;
            _authenticationStateProvider = authenticationStateProvider;
        }

        public async Task<bool> Login(string username, string password)
        {
            var response = await _httpClient.PostAsJsonAsync("https://your-api-endpoint.com/api/auth/login", new { username, password });

            if (response.IsSuccessStatusCode)
            {
                var result = await response.Content.ReadFromJsonAsync<LoginResult>();
                _token = result.Token;
                ((ApiAuthenticationStateProvider)_authenticationStateProvider).MarkUserAsAuthenticated(_token);
                return true;
            }

            return false;
        }

        public void Logout()
        {
            _token = null;
            ((ApiAuthenticationStateProvider)_authenticationStateProvider).MarkUserAsLoggedOut();
        }
    }

    public class LoginResult
    {
        public string Token { get; set; }
    }
}
