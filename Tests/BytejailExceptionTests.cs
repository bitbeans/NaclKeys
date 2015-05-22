using System;
using NaclKeys;
using NaclKeys.Exceptions;
using NUnit.Framework;
using Sodium;
using Sodium.Exceptions;

namespace Tests
{
    /// <summary>
    ///     Validate the Bytejail implementation.
    /// </summary>
    [TestFixture]
    public class BytejailExceptionTestsExceptionTests
    {
        [Test]
        [ExpectedException(typeof (ArgumentNullException))]
        public void GenerateBytejailKeyPairNoPartOneTest()
        {
            const string userInputPartOne = null;
            const string userInputPartTwo = "magnetometers payee induce tangibly polonaises unrestricted oilfield";
            KeyGenerator.GenerateBytejailKeyPair(userInputPartOne, userInputPartTwo);
        }

        [Test]
        [ExpectedException(typeof (ArgumentNullException))]
        public void GenerateBytejailKeyPairNoPartTwoTest()
        {
            const string userInputPartOne = "someone@example.com";
            const string userInputPartTwo = null;
            KeyGenerator.GenerateBytejailKeyPair(userInputPartOne, userInputPartTwo);
        }

        [Test]
        [ExpectedException(typeof (KeyOutOfRangeException))]
        public void EncodeBytejailKeyPairBadKeyTest()
        {
            KeyGenerator.EncodeBytejailPublicKey(null);
        }

        [Test]
        [ExpectedException(typeof (KeyOutOfRangeException))]
        public void EncodeBytejailKeyPairBadKeyTest2()
        {
            KeyGenerator.EncodeBytejailPublicKey(SodiumCore.GetRandomBytes(31));
        }

        [Test]
        [ExpectedException(typeof (CorruptIdentityException))]
        public void DecodeBytejailIdInvalidTest()
        {
            KeyGenerator.DecodeBytejailPublicKey("5bEJLKdSib9kWxkmskExaaLdRg8tVA2qsFBnfdQwkMe");
        }
    }
}