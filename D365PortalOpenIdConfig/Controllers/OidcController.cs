using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using D365PortalOpenIdConfig.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace D365PortalOpenIdConfig.Controllers
{
    [Route(".well-known")]
    [ApiController]
    public class OidcController : ControllerBase
    {
        private readonly string _domain;
        public OidcController(IConfiguration config)
        {
            _domain = config.GetValue<string>("D365Portal:Domain");
        }

        [HttpGet("openid-configuration", Name = "OIDCMetadata")]
        public ActionResult<OidcModel> Metadata()
        {
            return new OidcModel
            {
                // The issuer name is the portal domain
                Issuer = _domain,

                // Link to the JWKs endpoint
                JwksUri = Url.Link("JWKS", null),

                // Supported signing algorithms
                IdTokenSigningAlgValuesSupported = new[] { "RS256" },
            };
        }

        [HttpGet("keys", Name = "JWKS")]
        public async Task<ActionResult<JwksModel>> JwksDocument()
        {
            // Get the url of the public key
            var url = $"https://{_domain}/_services/auth/publickey";
            return new JwksModel
            {
                Keys = new[] { await GetKeyFromPublicKey(url) }
            };
        }

        private static async Task<JwksKeyModel> GetKeyFromPublicKey(string publicKeyUrl)
        {
            string content = null;
            using (var client = new HttpClient())
            {
                var response = await client.GetAsync(publicKeyUrl).ConfigureAwait(false);
                content = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
            }

            var rs256Token = content.Replace("-----BEGIN PUBLIC KEY-----", "");
            rs256Token = rs256Token.Replace("-----END PUBLIC KEY-----", "");
            rs256Token = rs256Token.Replace("\n", "");
            var keyBytes = Convert.FromBase64String(rs256Token);

            var asymmetricKeyParameter = PublicKeyFactory.CreateKey(keyBytes);
            var rsaKeyParameters = (RsaKeyParameters)asymmetricKeyParameter;

            var exponent = rsaKeyParameters.Exponent.ToByteArrayUnsigned();
            var modulus = rsaKeyParameters.Modulus.ToByteArrayUnsigned();

            return new JwksKeyModel()
            {
                N = ConvertToSafeBase64String(modulus),
                E = ConvertToSafeBase64String(exponent)
            };
        }

        private static string ConvertToSafeBase64String(byte[] bytes)
        {
            var base64 = Convert.ToBase64String(bytes);
            return base64.Replace("+", "-").Replace("/", "_");
        }
    }
}
