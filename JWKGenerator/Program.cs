using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;
using System.Net.Http.Headers;

namespace JWKGenerator
{
    class Program
    {

        public class JWK
        {
            public string kty { get; set; }
            public string crv { get; set; }
            public string x { get; set; }
            public string y { get; set; }
            public string alg { get; set; }
            public string use { get; set; }
            public string kid { get; set; }
        }


        static void Main(string[] args)
        {
            const string kid = "test";
            const string privateKeyPemFileName = "privateKey.pem";
            const string JWKFileName = "jwk.txt";

            Console.WriteLine("Enter a password that will be used to encrypt the private key:");

            string password = ReadPassword();

            ECDsaCng ecdsa = new ECDsaCng(ECCurve.NamedCurves.nistP256);

            ECParameters ecParams = ecdsa.ExportParameters(true);

            Console.WriteLine(Base64UrlEncoder.Encode(ecParams.D));

            byte[] privateKey = ecdsa.ExportEncryptedPkcs8PrivateKey(
                Encoding.UTF8.GetBytes(password),
                new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 1000)
            );

            privateKeyToPem(privateKey, privateKeyPemFileName);

            string jwk = JsonConvert.SerializeObject(new JWK
            {
                kty = "EC",
                crv = "P-256",
                x = Base64UrlEncoder.Encode(ecParams.Q.X),
                y = Base64UrlEncoder.Encode(ecParams.Q.Y),
                alg = "ES256",
                use = "sig",
                kid = kid
            });

            File.WriteAllText(JWKFileName, jwk);

            ImportAndVerifyJWK(privateKeyPemFileName, JWKFileName, password);
        }

        private static void privateKeyToPem(byte[] privateKey, string fileName)
        {
            string base64PrivateKey = Convert.ToBase64String(privateKey);

            StringBuilder pemData = new StringBuilder();
            pemData.AppendLine("-----BEGIN ENCRYPTED PRIVATE KEY-----");
            for (int i = 0; i < base64PrivateKey.Length; i += 64)
            {
                pemData.AppendLine(base64PrivateKey.Substring(i, Math.Min(64, base64PrivateKey.Length - i)));
            }
            pemData.AppendLine("-----END ENCRYPTED PRIVATE KEY-----");

            File.WriteAllText(fileName, pemData.ToString());
        }

        private static string ReadPassword()
        {
            string password = "";
            ConsoleKeyInfo key;

            do
            {
                key = Console.ReadKey(true);

                if (key.Key != ConsoleKey.Backspace && key.Key != ConsoleKey.Enter)
                {
                    password += key.KeyChar;
                    Console.Write("*");
                }
                else
                {
                    if (key.Key == ConsoleKey.Backspace && password.Length > 0)
                    {
                        password = password.Substring(0, password.Length - 1);
                        Console.Write("\b \b");
                    }
                }
            } while (key.Key != ConsoleKey.Enter);

            Console.WriteLine();
            return password;
        }

        private static void ImportAndVerifyJWK(string pemFileName, string jwkFileName, string password)
        {
            var now = DateTime.UtcNow;
            var handler = new JsonWebTokenHandler();

            JWK jwk = JsonConvert.DeserializeObject<JWK>(File.ReadAllText(jwkFileName));

            ECDsaCng key = new ECDsaCng();

            key.ImportParameters(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint
                {
                    X = Base64UrlEncoder.DecodeBytes(jwk.x),
                    Y = Base64UrlEncoder.DecodeBytes(jwk.y)
                }
            });

            var privateKeyPem = File.ReadAllText(pemFileName);

            key.ImportFromEncryptedPem(privateKeyPem, Encoding.UTF8.GetBytes(password));

            string token = handler.CreateToken(new SecurityTokenDescriptor
            {
                Issuer = "test",
                Audience = "test",
                Expires = now.AddSeconds(180),
                IssuedAt = now,
                Claims = new Dictionary<string, object> { { "test", "test" } },
                SigningCredentials = new SigningCredentials(new ECDsaSecurityKey(key) { KeyId = jwk.kid }, jwk.alg),
            });
            Console.WriteLine($"JWT-\n{token}\n");

            /*
                ***** DECODE JWT *****
                The JWT is decoded here to verify claims which are signed.
            */
            var securityHandler = new JwtSecurityTokenHandler();
            var jsonToken = securityHandler.ReadToken(token);
            var tokenString = jsonToken as JwtSecurityToken;
            Console.WriteLine($"Decoded JWT-\n{tokenString}\n");

        }

    }
}
