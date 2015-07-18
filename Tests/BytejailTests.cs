using System;
using NaclKeys;
using NUnit.Framework;
using Sodium;

namespace Tests
{
    /// <summary>
    ///     Validate the Bytejail implementation.
    /// </summary>
    [TestFixture]
    public class BytejailTests
    {
        [Test]
        public void GenerateBytejailKeyPairTest()
        {
            const string expected = "2PNPvrfYAQxhaGYaAzsWTYgEzymmQZ37jG2vJThBJHDcY6NzNoK";
            const string userInputPartOne = "someone@example.com";
            const string userInputPartTwo = "magnetometers payee induce tangibly polonaises unrestricted oilfield";
            Console.WriteLine("--- Generate bytejail KeyPair start ---");
            var zx = new Zxcvbn.Zxcvbn();
            Console.WriteLine(" - UserInputPartOne (utf8): " + userInputPartOne + " [" + userInputPartOne.Length + "]");
            Console.WriteLine(" - UserInputPartOne Entropy (~): " + zx.EvaluatePassword(userInputPartOne).Entropy);
            Console.WriteLine(" - UserInputPartTwo (utf8): " + userInputPartTwo + " [" + userInputPartTwo.Length + "]");
            Console.WriteLine(" - UserInputPartTwo Entropy (~): " + zx.EvaluatePassword(userInputPartTwo).Entropy);
            var keyPair = KeyGenerator.GenerateBytejailKeyPair(userInputPartOne, userInputPartTwo);
            Console.WriteLine(" - Private Key (hex): " + Utilities.BinaryToHex(keyPair.PrivateKey) + " [" +
                              keyPair.PrivateKey.Length + "]");
            Console.WriteLine(" - Public Key (hex): " + Utilities.BinaryToHex(keyPair.PublicKey) + " [" +
                              keyPair.PublicKey.Length + "]");
            var encodedPublicKey = KeyGenerator.EncodeBytejailPublicKey(keyPair.PublicKey);
            Console.WriteLine(" - Public ID (base58): " + encodedPublicKey + " [" +
                              encodedPublicKey.Length + "]");
            Console.WriteLine("--- Generate bytejail KeyPair end ---");
            Assert.AreEqual(expected, encodedPublicKey);
        }

        [Test]
        public void GenerateBytejailKeyPairExaggeratedTest()
        {
            const string expected = "2NjStPkM3Wr2JwqmH7gG7sRUhyGVG2FFewUajjbHrWRvjD5dpU3";
            // Test with KeePass generated inputs: length of 1024 exclude " and \
            const string userInputPartOne =
                "s7MgHRz?|dP@mmD7Q#Y~:m[]~Sjy7ad)t`tO&61B@o8l9p+['.V}y{L~])z{KM*:Cr8iw2t63^bpyn]b+x8Hh5#UG^gu>y1JgVj:4]NkYR<aE+T1C/3EaC9xxL#`n:=c0^_|eZm%-5T^yOM5DI9 ,XcG!Ej5=IuV0/j>bsYM'x[hQY#uwqNkm?0emxikBM$NHyzi9SLVd?E[)9x=.]d)f,]+9;;LJx|$ki|O-7PvZR/tF}9L&Hn!whdoklx+cyGiKCh=$qfXC9nuu;!21b=)as;R$%[d4[VESbTZ<tVMiZyT0|wDSCZTLT9v`QRg[6]m0Vgr]Ps@bp`J&P_4tfv:rJJ*P.z-!=]Nc07UwfUq2,C:vI1`LHrb$>ooM_S7{Lby/awngY9TMKAi[vj+V0u6'ot&gC?@6PtUP$8*iTeP`|~|)5^Y-_Nc@1]1jJO-.3+`r<BPFuDzah'H334*M^^8g;?v{9)P,=R[Uw*$D]w#oZm6yZ}c:5V^.*(F8S{?x!s#{)UL-}`VMdg:Y6Z]KE8%tjsE;Y)w+G>S@'K1Sf;]8<$`@Novad[whD.rahiJdfPetl`9 A)DH ZupA*6FIwU8n6Fa~Wf_-an*Etny9>GH}+5+F2!Y*?gD <P~`b~)xm~+9&2X;#K[iPj%F8.M/9/ifi?l1 )buY%2cIf,Rf/]NLgKoszB^ p$jmww1yfU)+lu#E-|)0lG7V{C!?]T`2cO/.k 3=C .`xcx&k sT1b&/.(8/Za)qO5w4)hDz'~tO]Y{ueGG[<<[L@kt1W~>Ct0ZsQNF{3RI!mIxS?L8CUTOEXxroeMhK;'p8xQ-_0Qr^St+0vJ;]#,?*0#F5146lN7MMQXN7b@Z)I>BQQ8S2'_WiBn)r$?Q~IE[)~b*`a8H8Y u`i4m# k^Z6%nk^.V_n5N?M.TS@?G=uE:%fpvhE8:)|Bm.fK.1w2|?Y}tpa)XuuhGt0DeWijlee2:8BqTNK2GDr!i2_M_?NnD2T{@G*Yc'gZ2Up(9}5]/NYd%^T$|0_";
            const string userInputPartTwo =
                ")DT~:*EnWSgY2])|aHjsEvBr#Xz$P);'b LEf23Qe}Q'8_('5X+AgMRsr?Xgl_j7X8|X&F},l&T cC3Z<$FXD.4H:q>xmr`8sR(T5=ub^`rcm#CgJo4Bt~krbpc{+RWtq-{ $)4pqd7fkDV>z+G3{@J=E;<Pn.|Sv5KA1~f5ir1FKMCh32~gULAn9DrT,uw4.-nDJmG&$W#~M'*Bx?^66ZGIyO@,(7M=otR;rxaJ!;W ;|?cVc?1K2lQvP[#zckA@}g$PC=AR>_KB~2gr*K$[y^SR29GUzrPPUme<Dl|?n|)(IAp+=tpfW')PNGlyM|EGiIfqrWWe3]!|v_MZHE,F(QS.<eA<.S#$!WOXw4nFLD./_LUVO;A3$)E6j|O$=QtkpDn^0zB/zh%j @gZ~0573D~PV-AyE?)_j|:.;61L>$ULRbx8b;RZw9KVN%N8u)py|[nA%8kWx}*H_gR RJA#a{&4Rc)4A'!0p@^y0T2k1[bIXA7aMv?Sc}{eXMBI lWV|$xPd+>txl==1u]}/L Hb?RlrY>?6oti9}2U>;b^GA0yM9-T;Lr'-s'mD2U<0jb|Thi<m]OYw[1zQo^H}#yu?W<z1[3fFTF2DgAF[(KCw1R5p R^=* 0:w#GC-@<cpIlxrU!z3#=9|ddbe)[=OUK?TB)mJ~1n+E!66==[lHuuD#voLtSF~/:>ZiPDbW)1ASkj)-+CwPAKPO:-KHNXod4c0#6kv0_@ntAp0~gUC4&uYZmMUsSiXB^+V<&1;/7q>.HR4qf!&aozAI7*HnKJs{z2DWJaR8D)>E9|2cAZ;b(_*8W_Kz;`ZIYpSK?+djw[%(fwHef$=xrk_T!z}Q81Vf3A(tj6#$teDUV@y^;|hGj A[I^YelK&yj/H5ZU~MS;hVUPOJ%GO$(LcE={`H|3R@~6GrasDK]sT*@/HD0 1?iFqh@YKr?iteSyhs&f9$^+US*MkeB)f=^n69_)1hEU~A<hK8-#MAbpzm4H>oWUx~Fk28zQfR[w!3[ -W cJSp_J ";
            Console.WriteLine("--- Generate bytejail KeyPair start ---");
            var zx = new Zxcvbn.Zxcvbn();
            Console.WriteLine(" - UserInputPartOne (utf8): " + userInputPartOne + " [" + userInputPartOne.Length + "]");
            Console.WriteLine(" - UserInputPartOne Entropy (~): " + zx.EvaluatePassword(userInputPartOne).Entropy);
            Console.WriteLine(" - UserInputPartTwo (utf8): " + userInputPartTwo + " [" + userInputPartTwo.Length + "]");
            Console.WriteLine(" - UserInputPartTwo Entropy (~): " + zx.EvaluatePassword(userInputPartTwo).Entropy);
            var keyPair = KeyGenerator.GenerateBytejailKeyPair(userInputPartOne, userInputPartTwo);
            Console.WriteLine(" - Private Key (hex): " + Utilities.BinaryToHex(keyPair.PrivateKey) + " [" +
                              keyPair.PrivateKey.Length + "]");
            Console.WriteLine(" - Public Key (hex): " + Utilities.BinaryToHex(keyPair.PublicKey) + " [" +
                              keyPair.PublicKey.Length + "]");
            var encodedPublicKey = KeyGenerator.EncodeBytejailPublicKey(keyPair.PublicKey);
            Console.WriteLine(" - Public ID (base58): " + encodedPublicKey + " [" +
                              encodedPublicKey.Length + "]");
            Console.WriteLine("--- Generate bytejail KeyPair end ---");
            Assert.AreEqual(expected, encodedPublicKey);
        }

        [Test]
        public void DecodeBytejailIdTest()
        {
            const string expected = "91e9b97edba152f97997cc7a4c5ad9c98558645b3a455f214f0202dccaa93229";
            var publicKey = KeyGenerator.DecodeBytejailPublicKey("2PonPHk28TBvBu3iADjXZAH5gPh8fTpQ2mh4eMbkLhPnMoc5Vwq");
            Assert.AreEqual(expected, Utilities.BinaryToHex(publicKey));
        }
    }
}
