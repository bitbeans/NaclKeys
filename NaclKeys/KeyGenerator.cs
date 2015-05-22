using System;
using System.Linq;
using System.Text;
using Base58Check;
using Blake2sCSharp;
using CryptSharp.Utility;
using NaclKeys.Exceptions;
using NaclKeys.Helper;
using Sodium;
using Sodium.Exceptions;

namespace NaclKeys
{
    public static class KeyGenerator
    {
        private const int PublicKeyBytes = 32;

        /// <summary>
        ///     Try to recognize the identity format.
        /// </summary>
        /// <param name="encodedPublicKey">A base58 encoded public identity.</param>
        public static void TryRecognizeIdentityFormat(string encodedPublicKey)
        {
            if (encodedPublicKey == null)
                throw new ArgumentNullException("encodedPublicKey", "encodedPublicKey cannot be null");

            throw new NotImplementedException("");
        }

        #region MiniLock Implementation

        /// <summary>
        ///     Generate a MiniLock Keypair from an email and a password.
        /// </summary>
        /// <param name="email">A valid (format) email address.</param>
        /// <param name="password">A password with a minimal entropy of 100.</param>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="InvalidMailException"></exception>
        /// <exception cref="LowEntropyException"></exception>
        /// <returns>A libsodium compatible KeyPair.</returns>
        public static KeyPair GenerateMiniLockKeyPair(string email, string password)
        {
            const int minPasswordEntropy = 100;

            if (email == null)
                throw new ArgumentNullException("email", "email cannot be null");

            // perform a simple email check
            if (!StringHelper.IsValidEmail(email))
                throw new InvalidMailException("the given email address seems to be invalid");

            if (password == null)
                throw new ArgumentNullException("password", "password cannot be null");

            var passwordEntropy = Zxcvbn.Zxcvbn.MatchPassword(password).Entropy;
            // check the entropy
            if (passwordEntropy < 100)
                throw new LowEntropyException(
                    string.Format(
                        "miniLock needs at least an entropy of {0}, the given password only has an entropy of {1}.",
                        minPasswordEntropy, passwordEntropy));

            var passwordHash = Blake2S.ComputeHash(Encoding.UTF8.GetBytes(password));
            var seed = SCrypt.ComputeDerivedKey(passwordHash, Encoding.UTF8.GetBytes(email), 131072, 8, 1, 1, 32);
            var keyPair = PublicKeyBox.GenerateKeyPair(seed);
            return keyPair;
        }

        /// <summary>
        ///     Encode a publicKey into miniLock format.
        /// </summary>
        /// <param name="publicKey">A 32 byte publicKey.</param>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <returns>A Base58 encoded publicKey.</returns>
        public static string EncodeMiniLockPublicKey(byte[] publicKey)
        {
            if (publicKey == null || publicKey.Length != PublicKeyBytes)
                throw new KeyOutOfRangeException("publicKey", (publicKey == null) ? 0 : publicKey.Length,
                    string.Format("key must be {0} bytes in length.", PublicKeyBytes));

            var final = ArrayHelpers.ConcatArrays(publicKey, Blake2S.ComputeHash(
                publicKey, 0, 32,
                new Blake2sConfig {OutputSizeInBytes = 1}));
            return Base58CheckEncoding.EncodePlain(final);
        }

        /// <summary>
        ///     Decode a miniLock ID into a byte array.
        /// </summary>
        /// <param name="encodedPublicKey">The miniLock ID.</param>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="CorruptIdentityException"></exception>
        /// <returns>A 32 byte array.</returns>
        public static byte[] DecodeMiniLockPublicKey(string encodedPublicKey)
        {
            if (encodedPublicKey == null)
                throw new ArgumentNullException("encodedPublicKey", "encodedPublicKey cannot be null");

            var raw = Base58CheckEncoding.DecodePlain(encodedPublicKey);
            var publicKey = ArrayHelpers.SubArray(raw, 0, 32);
            var checksum = ArrayHelpers.SubArray(raw, 32);
            // validate the checksum
            if (!checksum.SequenceEqual(Blake2S.ComputeHash(
                publicKey, 0, 32,
                new Blake2sConfig {OutputSizeInBytes = 1})))
                throw new CorruptIdentityException("the given identity seems to be an invalid miniLock ID");

            return publicKey;
        }

        #endregion

        #region CurveLock Implementation

        /// <summary>
        ///     Generate a CurveLock Keypair from an email and a password.
        /// </summary>
        /// <param name="email">A valid (format) email address.</param>
        /// <param name="password">A password.</param>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="InvalidMailException"></exception>
        /// <returns>A libsodium compatible KeyPair.</returns>
        public static KeyPair GenerateCurveLockKeyPair(string email, string password)
        {
            if (email == null)
                throw new ArgumentNullException("email", "email cannot be null");

            // perform a simple email check
            if (!StringHelper.IsValidEmail(email))
                throw new InvalidMailException("the given email address seems to be invalid");

            if (password == null)
                throw new ArgumentNullException("password", "password cannot be null");

            var salt = GenericHash.Hash(email, (byte[]) null, 32);
            var seed = PasswordHash.ScryptHashBinary(Encoding.UTF8.GetBytes(password), salt,
                PasswordHash.Strength.Moderate);
            var key = PublicKeyBox.GenerateKeyPair(seed);
            return key;
        }

        /// <summary>
        ///     Encode a publicKey into CurveLock format.
        /// </summary>
        /// <param name="publicKey">A 32 byte publicKey.</param>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <returns>A Base58 encoded publicKey.</returns>
        public static string EncodeCurveLockPublicKey(byte[] publicKey)
        {
            if (publicKey == null || publicKey.Length != PublicKeyBytes)
                throw new KeyOutOfRangeException("publicKey", (publicKey == null) ? 0 : publicKey.Length,
                    string.Format("key must be {0} bytes in length.", PublicKeyBytes));

            var version = new byte[] {0x0A};
            var final = ArrayHelpers.ConcatArrays(version, publicKey);
            return Base58CheckEncoding.Encode(final);
        }

        /// <summary>
        ///     Decode a CurveLock ID into a byte array.
        /// </summary>
        /// <param name="encodedPublicKey">The CurveLock ID.</param>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="CorruptIdentityException"></exception>
        /// <returns>A 32 byte array.</returns>
        public static byte[] DecodeCurveLockPublicKey(string encodedPublicKey)
        {
            if (encodedPublicKey == null)
                throw new ArgumentNullException("encodedPublicKey", "encodedPublicKey cannot be null");

            try
            {
                var raw = Base58CheckEncoding.Decode(encodedPublicKey);
                var version = ArrayHelpers.SubArray(raw, 0, 1);
                if (!version.SequenceEqual(new byte[] {0x0A}))
                    throw new FormatException("invalid version");

                var publicKey = ArrayHelpers.SubArray(raw, 1);
                return publicKey;
            }
            catch (FormatException)
            {
                throw new CorruptIdentityException("the given identity seems to be an invalid CurveLock ID");
            }
        }

        #endregion

        #region bytejail Implementation

        /// <summary>
        ///     Generate a bytejail Keypair from any input.
        /// </summary>
        /// <param name="userInputPartOne">Anything but not null</param>
        /// <param name="userInputPartTwo">Anything but not null</param>
        /// <exception cref="ArgumentNullException"></exception>
        /// <returns>A libsodium compatible KeyPair.</returns>
        public static KeyPair GenerateBytejailKeyPair(string userInputPartOne, string userInputPartTwo)
        {
            if (userInputPartOne == null)
                throw new ArgumentNullException("userInputPartOne", "userInputPartOne cannot be null");

            if (userInputPartTwo == null)
                throw new ArgumentNullException("userInputPartTwo", "userInputPartTwo cannot be null");

            var salt = GenericHash.Hash(userInputPartOne, (byte[]) null, 32);
            var seed = PasswordHash.ScryptHashBinary(GenericHash.Hash(userInputPartTwo, (byte[]) null, 64), salt,
                PasswordHash.Strength.Moderate);
            var key = PublicKeyBox.GenerateKeyPair(seed);
            return key;
        }

        /// <summary>
        ///     Encode a publicKey into bytejail format.
        /// </summary>
        /// <param name="publicKey">A 32 byte publicKey.</param>
        /// <exception cref="KeyOutOfRangeException"></exception>
        /// <returns>A Base58 encoded publicKey.</returns>
        public static string EncodeBytejailPublicKey(byte[] publicKey)
        {
            if (publicKey == null || publicKey.Length != PublicKeyBytes)
                throw new KeyOutOfRangeException("publicKey", (publicKey == null) ? 0 : publicKey.Length,
                    string.Format("key must be {0} bytes in length.", PublicKeyBytes));

            var version = new byte[] {0x0A};
            var final = ArrayHelpers.ConcatArrays(version, publicKey, CalculateBytejailChecksum(publicKey));
            return Base58CheckEncoding.EncodePlain(final);
        }

        /// <summary>
        ///     Decode a bytejail ID into a byte array.
        /// </summary>
        /// <param name="encodedPublicKey">The bytejail ID.</param>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="CorruptIdentityException"></exception>
        /// <returns>A 32 byte array.</returns>
        public static byte[] DecodeBytejailPublicKey(string encodedPublicKey)
        {
            if (encodedPublicKey == null)
                throw new ArgumentNullException("encodedPublicKey", "encodedPublicKey cannot be null");

            try
            {
                var raw = Base58CheckEncoding.DecodePlain(encodedPublicKey);
                var version = ArrayHelpers.SubArray(raw, 0, 1);
                if (!version.SequenceEqual(new byte[] {0x0A}))
                    throw new FormatException("invalid version");

                var publicKey = ArrayHelpers.SubArray(raw, 1, 32);
                var checksum = CalculateBytejailChecksum(publicKey);
                var givenChecksum = ArrayHelpers.SubArray(raw, 33);
                if (!checksum.SequenceEqual(givenChecksum))
                    throw new CorruptIdentityException("the given identity seems to be an invalid bytejail ID");

                return publicKey;
            }
            catch (FormatException)
            {
                throw new CorruptIdentityException("the given identity seems to be an invalid bytejail ID");
            }
        }

        /// <summary>
        ///     Calculate a checksum for a bytejail ID.
        /// </summary>
        /// <param name="publicKey">A 32 byte publicKey</param>
        /// <returns>A 4-byte array.</returns>
        private static byte[] CalculateBytejailChecksum(byte[] publicKey)
        {
            if (publicKey == null || publicKey.Length != PublicKeyBytes)
                throw new KeyOutOfRangeException("publicKey", (publicKey == null) ? 0 : publicKey.Length,
                    string.Format("key must be {0} bytes in length.", PublicKeyBytes));

            var hashRound1 = GenericHash.Hash(publicKey, null, 64);
            var hashRound2 = GenericHash.Hash(hashRound1, null, 64);

            var result = new byte[4];
            Buffer.BlockCopy(hashRound2, 0, result, 0, result.Length);

            return result;
        }

        #endregion
    }
}