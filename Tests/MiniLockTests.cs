using System;
using NaclKeys;
using NUnit.Framework;
using Sodium;

namespace Tests
{
    /// <summary>
    ///     Validate the miniLock implementation.
    /// </summary>
    [TestFixture]
    public class MiniLockTests
    {
        [Test]
        public void GenerateMiniLockKeyPairTest()
        {
            const string expected = "Cz5bEJLKdSib9kWxkmskExaaLdRg8tVA2qsFBnfdQwkMe";
            const string email = "someone@example.com";
            const string password = "magnetometers payee induce tangibly polonaises unrestricted oilfield";
            Console.WriteLine("--- Generate miniLock KeyPair start ---");
            var zx = new Zxcvbn.Zxcvbn();
            Console.WriteLine(" - E-Mail (utf8): " + email + " [" + email.Length + "]");
            Console.WriteLine(" - E-Mail Entropy (~): " + zx.EvaluatePassword(email).Entropy);
            Console.WriteLine(" - Password (utf8): " + password + " [" + password.Length + "]");
            Console.WriteLine(" - Password Entropy (~): " + zx.EvaluatePassword(password).Entropy);
            var keyPair = KeyGenerator.GenerateMiniLockKeyPair(email, password);
            Console.WriteLine(" - Private Key (hex): " + Utilities.BinaryToHex(keyPair.PrivateKey) + " [" +
                              keyPair.PrivateKey.Length + "]");
            Console.WriteLine(" - Public Key (hex): " + Utilities.BinaryToHex(keyPair.PublicKey) + " [" +
                              keyPair.PublicKey.Length + "]");
            var encodedPublicKey = KeyGenerator.EncodeMiniLockPublicKey(keyPair.PublicKey);
            Console.WriteLine(" - Public ID (base58): " + encodedPublicKey + " [" +
                              encodedPublicKey.Length + "]");
            Console.WriteLine("--- Generate miniLock KeyPair end ---");
            Assert.AreEqual(expected, encodedPublicKey);
        }

        [Test]
        public void DecodeMiniLockIdTest()
        {
            const string expected = "28579770b321769c2ad24873287152fe5ab928bb54fff460c808e4a9f70a7d69";
            var publicKey = KeyGenerator.DecodeMiniLockPublicKey("Cz5bEJLKdSib9kWxkmskExaaLdRg8tVA2qsFBnfdQwkMe");
            Assert.AreEqual(expected, Utilities.BinaryToHex(publicKey));
        }
    }
}