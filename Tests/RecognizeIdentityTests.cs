using NaclKeys;
using NaclKeys.Models;
using NUnit.Framework;

namespace Tests
{
    /// <summary>
    ///     Validate the recognize implementation.
    /// </summary>
    [TestFixture]
    public class RecognizeIdentityTests
    {
        [Test]
        public void RecognizeIdentityTest()
        {
            const string minilock = "Cz5bEJLKdSib9kWxkmskExaaLdRg8tVA2qsFBnfdQwkMe";
            const string curvelock = "NMgsvm7ytEHdGEuj9QEaoW7uH2tMQe9Ji2h9viw7kzFkgApVkH";
            const string bytejail = "2PonPHk28TBvBu3iADjXZAH5gPh8fTpQ2mh4eMbkLhPnMoc5Vwq";
            const string unknown = "2PfXEU8XZedzDv3xt7pfAiCLTt3az1EeFV7zwaRLhKKd7ZAyR";
            Assert.AreEqual(KeyType.MiniLock, KeyGenerator.TryRecognizeIdentityFormat(minilock));
            Assert.AreEqual(KeyType.CurveLock, KeyGenerator.TryRecognizeIdentityFormat(curvelock));
            Assert.AreEqual(KeyType.Bytejail, KeyGenerator.TryRecognizeIdentityFormat(bytejail));
            Assert.AreEqual(KeyType.Unknown, KeyGenerator.TryRecognizeIdentityFormat(unknown));
        }
    }
}