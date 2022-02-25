using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Runtime.CompilerServices;
using System.Text;
using System.Windows.Input;
using Xamarin.Essentials;
using Xamarin.Forms;
using XamarinIdentityServer.Services;

namespace XamarinIdentityServer.ViewModels
{ 
    public class MainViewModel : INotifyPropertyChanged
    {
        private readonly HttpClient _httpClient = new HttpClient();
       // private const string AuthorityUrl = "https://azuks-chi-cross-identity-sts-ai-wa-d1.azurewebsites.net/";
        private const string AuthorityUrl = "https://b2b.poolcorp.com/identity";
        private Credentials _credentials;
        private readonly OidcIdentityService _oidcIdentityService;

        string clientID = "1007422f-964b-4f79-98c4-e76f9b998c6a";
        string redirectUrl = "https://poolcorp.commerce.insitesandbox.com/identity/externalcallback";
        string postLogoutRedirectUrl = "";
        string scope = "openid profile email";
        string clientSecret = "";
        public MainViewModel()
        {
            _oidcIdentityService = new OidcIdentityService(clientID, redirectUrl, postLogoutRedirectUrl, scope, AuthorityUrl, clientSecret);
            ExecuteLogin = new Command(Login);
            ExecuteRefresh = new Command(RefreshTokens);
            ExecuteLogout = new Command(Logout);
            ExecuteGetInfo = new Command(GetInfo);
            ExecuteCopyAccessToken = new Command(async () => await Clipboard.SetTextAsync(_credentials?.AccessToken));
            ExecuteCopyIdentityToken = new Command(async () => await Clipboard.SetTextAsync(_credentials?.IdentityToken));
        }

        public ICommand ExecuteLogin { get; }
        public ICommand ExecuteRefresh { get; }
        public ICommand ExecuteLogout { get; }
        public ICommand ExecuteGetInfo { get; }
        public ICommand ExecuteCopyAccessToken { get; }
        public ICommand ExecuteCopyIdentityToken { get; }

        public string TokenExpirationText => "Access Token expires at: " + _credentials?.AccessTokenExpiration;
        public string AccessTokenText => "Access Token: " + _credentials?.AccessToken;
        public string IdTokenText => "Id Token: " + _credentials?.IdentityToken;
        public bool IsLoggedIn => _credentials != null;
        public bool IsNotLoggedIn => _credentials == null;

        public event PropertyChangedEventHandler PropertyChanged;

        protected virtual void OnPropertyChanged([CallerMemberName] string propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }

        private async void GetInfo()
        {
            var url = Path.Combine(AuthorityUrl, "manage", "index");
            var response = await _httpClient.GetAsync(url);
            if (response.StatusCode == HttpStatusCode.Unauthorized)
            {
                if (string.IsNullOrEmpty(_credentials?.RefreshToken))
                {
                    // no valid refresh token exists => authenticate
                    await _oidcIdentityService.Authenticate();
                }
                else
                {
                    // we have a valid refresh token => refresh tokens
                    await _oidcIdentityService.RefreshToken(_credentials.RefreshToken);
                }
            }

            Debug.WriteLine(await response.Content.ReadAsStringAsync());
        }

        private async void Login()
        {
            Credentials credentials = await _oidcIdentityService.Authenticate();
            UpdateCredentials(credentials);

            _httpClient.DefaultRequestHeaders.Authorization = credentials.IsError
                ? null
                : new AuthenticationHeaderValue("bearer", credentials.AccessToken);
        }

        private async void RefreshTokens()
        {
            if (_credentials?.RefreshToken == null) return;
            Credentials credentials = await _oidcIdentityService.RefreshToken(_credentials.RefreshToken);
            UpdateCredentials(credentials);
        }

        private async void Logout()
        {
            await _oidcIdentityService.Logout(_credentials?.IdentityToken);
            _credentials = null;
            OnPropertyChanged(nameof(TokenExpirationText));
            OnPropertyChanged(nameof(AccessTokenText));
            OnPropertyChanged(nameof(IdTokenText));
            OnPropertyChanged(nameof(IsLoggedIn));
            OnPropertyChanged(nameof(IsNotLoggedIn));
        }

        private void UpdateCredentials(Credentials credentials)
        {
            _credentials = credentials;
            OnPropertyChanged(nameof(TokenExpirationText));
            OnPropertyChanged(nameof(AccessTokenText));
            OnPropertyChanged(nameof(IdTokenText));
            OnPropertyChanged(nameof(IsLoggedIn));
            OnPropertyChanged(nameof(IsNotLoggedIn));
        }
    }
}
