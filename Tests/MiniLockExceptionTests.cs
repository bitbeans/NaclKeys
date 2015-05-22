using System;
using NaclKeys;
using NaclKeys.Exceptions;
using NUnit.Framework;
using Sodium;
using Sodium.Exceptions;

namespace Tests
{
    /// <summary>
    ///     Validate the miniLock implementation.
    /// </summary>
    [TestFixture]
    public class MiniLockExceptionTests
    {
        [Test]
        [ExpectedException(typeof (InvalidMailException))]
        public void GenerateMiniLockKeyPairBadMailTest()
        {
            const string email = "someoneexample.com";
            const string password = "magnetometers payee induce tangibly polonaises unrestricted oilfield";
            KeyGenerator.GenerateMiniLockKeyPair(email, password);
        }

        [Test]
        [ExpectedException(typeof (ArgumentNullException))]
        public void GenerateMiniLockKeyPairNoMailTest()
        {
            const string email = null;
            const string password = "magnetometers payee induce tangibly polonaises unrestricted oilfield";
            KeyGenerator.GenerateMiniLockKeyPair(email, password);
        }

        [Test]
        [ExpectedException(typeof (LowEntropyException))]
        public void GenerateMiniLockKeyPairBadPasswordTest()
        {
            const string email = "someone@example.com";
            const string password = "magnetometers";
            KeyGenerator.GenerateMiniLockKeyPair(email, password);
        }

        [Test]
        [ExpectedException(typeof (ArgumentNullException))]
        public void GenerateMiniLockKeyPairNoPasswordTest()
        {
            const string email = "someone@example.com";
            const string password = null;
            KeyGenerator.GenerateMiniLockKeyPair(email, password);
        }

        [Test]
        [ExpectedException(typeof (KeyOutOfRangeException))]
        public void EncodeMiniLockKeyPairBadKeyTest()
        {
            KeyGenerator.EncodeMiniLockPublicKey(null);
        }

        [Test]
        [ExpectedException(typeof (KeyOutOfRangeException))]
        public void EncodeMiniLockKeyPairBadKeyTest2()
        {
            KeyGenerator.EncodeMiniLockPublicKey(SodiumCore.GetRandomBytes(31));
        }

        [Test]
        [ExpectedException(typeof (CorruptIdentityException))]
        public void DecodeMiniLockIdInvalidTest()
        {
            KeyGenerator.DecodeMiniLockPublicKey("5bEJLKdSib9kWxkmskExaaLdRg8tVA2qsFBnfdQwkMe");
        }
    }
}