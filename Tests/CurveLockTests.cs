using System;
using NaclKeys;
using NUnit.Framework;
using Sodium;

namespace Tests
{
    /// <summary>
    ///     Validate the CurveLock implementation.
    /// </summary>
    [TestFixture]
    public class CurveLockTests
    {
        [Test]
        public void GenerateCurveLockKeyPairTest()
        {
            const string expected = "NMgsvm7ytEHdGEuj9QEaoW7uH2tMQe9Ji2h9viw7kzFkgApVkH";
            const string email = "someone@example.com";
            const string password = "magnetometers payee induce tangibly polonaises unrestricted oilfield";
            Console.WriteLine("--- Generate CurveLock KeyPair start ---");
            var zx = new Zxcvbn.Zxcvbn();
            Console.WriteLine(" - E-Mail (utf8): " + email + " [" + email.Length + "]");
            Console.WriteLine(" - E-Mail Entropy (~): " + zx.EvaluatePassword(email).Entropy);
            Console.WriteLine(" - Password (utf8): " + password + " [" + password.Length + "]");
            Console.WriteLine(" - Password Entropy (~): " + zx.EvaluatePassword(password).Entropy);
            var keyPair = KeyGenerator.GenerateCurveLockKeyPair(email, password);
            Console.WriteLine(" - Private Key (hex): " + Utilities.BinaryToHex(keyPair.PrivateKey) + " [" +
                              keyPair.PrivateKey.Length + "]");
            Console.WriteLine(" - Public Key (hex): " + Utilities.BinaryToHex(keyPair.PublicKey) + " [" +
                              keyPair.PublicKey.Length + "]");
            var encodedPublicKey = KeyGenerator.EncodeCurveLockPublicKey(keyPair.PublicKey);
            Console.WriteLine(" - Public ID (base58): " + encodedPublicKey + " [" +
                              encodedPublicKey.Length + "]");
            Console.WriteLine("--- Generate CurveLock KeyPair end ---");
            Assert.AreEqual(expected, encodedPublicKey);
        }

        [Test]
        public void DecodeCurveLockIdTest()
        {
            const string expected = "fc97747205619f7a7c6e5b6c9179d38a87f33bf3c350c8c1ce06df26999df256";
            var publicKey = KeyGenerator.DecodeCurveLockPublicKey("NMgsvm7ytEHdGEuj9QEaoW7uH2tMQe9Ji2h9viw7kzFkgApVkH");
            Assert.AreEqual(expected, Utilities.BinaryToHex(publicKey));
        }
    }
}