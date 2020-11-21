using System;
using System.Configuration;

namespace ProjectBlake.Models
{
    public class DocuSignModel
    {
        public string OAuthBaseUrl { get; set; }
        
        public string IntegrationId { get; set; }

        public string ClientId => IntegrationId;

        public string ClientSecret { get; set; }

        public string Scopes { get; set; }

        public string Callback { get; set; }

        /// <summary>
        /// Base64 Private Key
        /// </summary>
        public string PrivateKey { get; set; }

        public byte[] PrivateKeyBytes => Convert.FromBase64String(PrivateKey);

        public string ConsentUrl => $"https://{OAuthBaseUrl}/oauth/auth?response_type=code&scope={Scopes}&client_id={IntegrationId}&redirect_uri={Callback}";

        public static DocuSignModel Default()
        {
            var model = new DocuSignModel
            {
                OAuthBaseUrl = ConfigurationManager.AppSettings["baseUrl"],
                IntegrationId = ConfigurationManager.AppSettings["integrationId"],
                ClientSecret = ConfigurationManager.AppSettings["dsSecret"],
                Scopes = ConfigurationManager.AppSettings["scopes"],
                Callback = ConfigurationManager.AppSettings["callback"],
                PrivateKey = ConfigurationManager.AppSettings["privateKey"]
            };

            return model;
        }
    }
}