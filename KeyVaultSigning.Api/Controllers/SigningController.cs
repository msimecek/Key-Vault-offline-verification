using Azure.Identity;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Security.Cryptography;
using System.Text;

namespace KeyVaultSigning.Api.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class SigningController : ControllerBase
    {
        const string keyVaultName = "dxsigning-proto";
        const string keyName = "testkey";
        string keyVaultUrl = $"https://{keyVaultName}.vault.azure.net/";

        private static JsonWebKey _key; // for method 1
        private static Uri _keyId;
        private static RSA _rsa; // for method 2

        private readonly ILogger<SigningController> _logger;

        public SigningController(ILogger<SigningController> logger)
        {
            _logger = logger;

            // Fake singleton for demonstration.
            // Get key only on first request.
            if (_keyId == null)
            {
                var _keyClient = new KeyClient(new Uri(keyVaultUrl), new DefaultAzureCredential());
                
                // Reach out to Key Vault and retrieve public key information.
                // This is all that's needed to construct the RSA object.
                var key = _keyClient.GetKey(keyName).Value;

                // Storing Key ID for signing purposes.
                _keyId = key.Id;

                // Storing the JsonWebKey representation to be used with preview SDK.
                _key = key.Key;

                // Without preview SDK we build RSA from the JsonWebKey.
                RSAParameters rsaKeyInfo = new RSAParameters();
                rsaKeyInfo.Modulus = key.Key.N;     // N = RSA key modulus
                rsaKeyInfo.Exponent = key.Key.E;    // E = RSA public exponent

                _rsa = RSA.Create();
                _rsa.ImportParameters(rsaKeyInfo);
            }
        }

        [HttpPost("sign")]
        public ActionResult Sign([FromBody] string text)
        {
            // Initialize the remote crypto client for our particular key with Azure credentials of this client application.
            var rsaCryptoClient = new CryptographyClient(_keyId, new DefaultAzureCredential());

            // Use RSA SHA-256 to sign the text.
            var rsaSignDataResult = rsaCryptoClient.SignData(SignatureAlgorithm.RS256, Encoding.UTF8.GetBytes(text));
            
            _logger.LogInformation($"Signed data using the algorithm {rsaSignDataResult.Algorithm}, with key {rsaSignDataResult.KeyId}. The resulting signature is {Convert.ToBase64String(rsaSignDataResult.Signature)}.");

            // Return signature.
            var res = new SignResponse()
            {
                Algorithm = rsaSignDataResult.Algorithm.ToString(),
                Signature = Convert.ToBase64String(rsaSignDataResult.Signature)
            };

            return Ok(res);
        }

        [HttpPost("verify")]
        public ActionResult Verify([FromBody] VerifyRequest req)
        {
            if (req.Algorithm != SignatureAlgorithm.RS256.ToString())
            {
                return BadRequest("Only RS256 (RSA SHA-256) algorithm is expected.");
            }

            //
            // Using the preview KeyVault SDK.
            //
            var rsaCryptoClient = new CryptographyClient(_key);
            VerifyResult rsaVerifyDataResult = rsaCryptoClient.VerifyData(SignatureAlgorithm.RS256, Encoding.UTF8.GetBytes(req.Data), Convert.FromBase64String(req.Signature));
            if (rsaVerifyDataResult.IsValid)
            {
                return Ok("Valid");
            }
            else
            {
                return BadRequest("Invalid");
            }

            //
            // Alternative method without the preview SDK.
            //
            //// Reusing the RSA object which contains our public key.
            //RSAPKCS1SignatureDeformatter rsaDeformatter = new RSAPKCS1SignatureDeformatter(_rsa);

            //// Hash algorithm used for signing was SHA-256.
            //// There could be additional logic, which adapts to the algorithm specified in the request, but that's not the scope here.
            //rsaDeformatter.SetHashAlgorithm(HashAlgorithmName.SHA256.Name);

            //byte[] dataBytes = Encoding.UTF8.GetBytes(req.Data);
            //byte[] digest = null;

            //// Hashing data with SHA-256.
            //using (HashAlgorithm hashAlgo = SHA256.Create())
            //{
            //    digest = hashAlgo.ComputeHash(dataBytes);
            //    _logger.LogInformation($"Created a hash from data: {digest}.");
            //}

            //// Verifying if the provided signature is correct for the data hash.
            //if (rsaDeformatter.VerifySignature(digest, Convert.FromBase64String(req.Signature)))
            //{
            //    _logger.LogInformation("Signature is valid.");
            //    return Ok("Valid");
            //}
            //else
            //{
            //    _logger.LogInformation("Signature is invalid.");
            //    return BadRequest("Invalid");
            //}


        }

        public record SignResponse
        {
            public string Algorithm { get; set; }
            public string Signature { get; set; }
        }

        public record VerifyRequest
        {
            public string Data { get; set; }
            public string Signature { get; set; }
            public string Algorithm { get; set; }
        }
    }
}
