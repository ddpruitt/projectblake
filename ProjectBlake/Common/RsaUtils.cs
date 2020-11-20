using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

namespace ProjectBlake.Common
{
    /// <summary>
    /// this code extracted from the Docusign C# Api
    /// Docusign C# API is MIT License!!!
    /// https://github.com/docusign/docusign-csharp-client/blob/7185c466bf9ccd93599637e1901022bc1c5eead6/sdk/src/DocuSign.eSign/Client/ApiClient.cs#L966
    /// ApiClient.RequestJWTUserToken
    /// </summary>
    public class RsaUtils
    {
        public static string RequestJWTUserToken(string clientId, string userId, string oauthBasePath, byte[] privateKeyBytes, int expiresInHours, List<string> scopes = null)
        {
            string privateKey = Encoding.UTF8.GetString(privateKeyBytes);

            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler
            {
                SetDefaultTimesOnTokenCreation = false
            };

            SecurityTokenDescriptor descriptor = new SecurityTokenDescriptor()
            {
                Expires = DateTime.UtcNow.AddHours(expiresInHours),
                IssuedAt = DateTime.UtcNow,
            };

            scopes = scopes ?? new List<string> { "signature" };

            descriptor.Subject = new ClaimsIdentity();
            descriptor.Subject.AddClaim(new Claim("scope", String.Join(" ", scopes)));
            descriptor.Subject.AddClaim(new Claim("aud", oauthBasePath));
            descriptor.Subject.AddClaim(new Claim("iss", clientId));

            if (!string.IsNullOrEmpty(userId))
            {
                descriptor.Subject.AddClaim(new Claim("sub", userId));
            }
            else
            {
                throw new Exception("User Id not supplied or is invalid!");
            }

            if (!string.IsNullOrEmpty(privateKey))
            {
                var rsa = CreateRSAKeyFromPem(privateKey);
                RsaSecurityKey rsaKey = new RsaSecurityKey(rsa);
                descriptor.SigningCredentials = new SigningCredentials(rsaKey, SecurityAlgorithms.RsaSha256Signature);
            }
            else
            {
                throw new Exception("Private key not supplied or is invalid!");
            }

            var token = handler.CreateToken(descriptor);
            string jwtToken = handler.WriteToken(token);

            return jwtToken;
        }

        private static RSA CreateRSAKeyFromPem(string key)
        {
            TextReader reader = new StringReader(key);
            PemReader pemReader = new PemReader(reader);

            object result = pemReader.ReadObject();

            RSA provider = RSA.Create();

            if (result is AsymmetricCipherKeyPair keyPair)
            {
                var rsaParams = DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters)keyPair.Private);
                provider.ImportParameters(rsaParams);
                return provider;
            }
            else if (result is RsaKeyParameters keyParameters)
            {
                var rsaParams = DotNetUtilities.ToRSAParameters(keyParameters);
                provider.ImportParameters(rsaParams);
                return provider;
            }

            throw new Exception("Unexpected PEM type");
        }
    }
}