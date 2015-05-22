using System;
using NaclKeys;
using NaclKeys.Exceptions;
using NUnit.Framework;
using Sodium;
using Sodium.Exceptions;

namespace Tests
{
    /// <summary>
    ///     Validate the CurveLock implementation.
    /// </summary>
    [TestFixture]
    public class CurveLockExceptionTests
    {
        [Test]
        [ExpectedException(typeof (InvalidMailException))]
        public void GenerateCurveLockKeyPairBadMailTest()
        {
            const string email = "someoneexample.com";
            const string password = "magnetometers payee induce tangibly polonaises unrestricted oilfield";
            KeyGenerator.GenerateCurveLockKeyPair(email, password);
        }

        [Test]
        [ExpectedException(typeof (ArgumentNullException))]
        public void GenerateCurveLockKeyPairNoMailTest()
        {
            const string email = null;
            const string password = "magnetometers payee induce tangibly polonaises unrestricted oilfield";
            KeyGenerator.GenerateCurveLockKeyPair(email, password);
        }

        [Test]
        [ExpectedException(typeof (ArgumentNullException))]
        public void GenerateCurveLockKeyPairNoPasswordTest()
        {
            const string email = "someone@example.com";
            const string password = null;
            KeyGenerator.GenerateCurveLockKeyPair(email, password);
        }

        [Test]
        [ExpectedException(typeof (KeyOutOfRangeException))]
        public void EncodeCurveLockKeyPairBadKeyTest()
        {
            KeyGenerator.EncodeCurveLockPublicKey(null);
        }

        [Test]
        [ExpectedException(typeof (KeyOutOfRangeException))]
        public void EncodeCurveLockKeyPairBadKeyTest2()
        {
            KeyGenerator.EncodeCurveLockPublicKey(SodiumCore.GetRandomBytes(31));
        }

        [Test]
        [ExpectedException(typeof (CorruptIdentityException))]
        public void DecodeCurveLockIdInvalidTest()
        {
            KeyGenerator.DecodeCurveLockPublicKey("5bEJLKdSib9kWxkmskExaaLdRg8tVA2qsFBnfdQwkMe");
        }
    }
}