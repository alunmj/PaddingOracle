using Microsoft.VisualStudio.TestTools.UnitTesting;

using PadOracle;

namespace POUnitTest
{
    [TestClass]
    public class UnitTest1
    {
        [TestMethod]
        public void TestMethod1()
        {
        }
        [TestMethod]
        public void UnpackUrl()
        {
            string innob = "http://localhost:3001/path1/path2/?cipher=MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MA%3D%3D&iv=YWJjZGVmZ2hpamtsbW5vcA%3D%3D";
            UrlParser pu = new UrlParser(innob,
                "MTI.*5MA%3D%3D","YWJ.*vcA%3D%3D",16,POEncoding.b64);
            string outnob = pu.URLTest();
            Assert.AreEqual(outnob, innob);
        }
    }
}
