using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using ProjectBlake.Models;

namespace ProjectBlake.Common
{
    public static class DocuSignToken
    {
        public static async Task<dynamic> BuildJwtAndExchangeWithDocusign(string userId)
        {
            var model = DocuSignModel.Default();

            int expiresInHours = 1;

            using (var http = new HttpClient())
            {
                string token = RsaUtils.RequestJWTUserToken(model.ClientId, userId, model.OAuthBaseUrl, model.PrivateKeyBytes, expiresInHours);

                var @params = new List<KeyValuePair<string, string>>
                {
                    new KeyValuePair<string, string>("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                    new KeyValuePair<string, string>("assertion", token)
                };

                var data = new FormUrlEncodedContent(@params);

                var response = await http.PostAsync($"https://{model.OAuthBaseUrl}/oauth/token", data);
                string content = await response.Content.ReadAsStringAsync();
                content = JToken.Parse(content).ToString(Formatting.Indented);

                return new { token, content };
            }
        }

        public static async Task<string> GetOauthUser(string token)
        {
            var model = DocuSignModel.Default();

            JObject jobj = JObject.Parse(token);
            string accessToken = jobj["access_token"]?.ToString() ?? string.Empty;

            if (string.IsNullOrWhiteSpace(accessToken)) return string.Empty;

            using (var http = new HttpClient())
            {
                http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

                var userResponse = await http.GetAsync($"https://{model.OAuthBaseUrl}/oauth/userinfo");

                string userContent = await userResponse.Content.ReadAsStringAsync();
                userContent = JToken.Parse(userContent).ToString(Formatting.Indented);

                return userContent;

                // https://account-d.docusign.com/oauth/userinfo 
                // https://demo.docusign.net/restapi/v2/accounts/8db1b68f-f51a-4c63-a7df-40f65d327b29/users?email=ryan.rodemoyer@mortgagecadence.com
                // https://account-d.docusign.com/oauth/userinfo
            }
        }

        public static async Task<string> GetAuthGrantAccessToken(string code)
        {
            var model = DocuSignModel.Default();

            string basic = $"{model.IntegrationId}:{model.ClientSecret}";
            byte[] bytes = Encoding.UTF8.GetBytes(basic);
            string base64 = Convert.ToBase64String(bytes);

            // data "grant_type=authorization_code&code=YOUR_AUTHORIZATION_CODE"

            using (var http = new HttpClient())
            {
                http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", base64);

                var @params = new List<KeyValuePair<string, string>>
                {
                    new KeyValuePair<string, string>("grant_type", "authorization_code"),
                    new KeyValuePair<string, string>("code", code)
                };

                var data = new FormUrlEncodedContent(@params);

                var response = await http.PostAsync($"https://{model.OAuthBaseUrl}/oauth/token", data);

                string content = await response.Content.ReadAsStringAsync();
                return content;
            }
        }

    }
}