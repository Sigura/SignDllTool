namespace SignDllTool.Tests
{
    using System;
    using System.IO;
    using System.Linq;
    using NUnit.Framework;

    [TestFixture]
    public class SignDllToolTests
    {
        const string PublickToken = @"19 F8 A1 69 C0 70 41 C6";

        [Test]
        public void Should_Work_Get_File_Info_Key()
        {
            Program.GetKeyFile(new [] {@"/key:sign.snk"});
        }

        [Test]
        public void Should_Get_Public_Key()
        {
            var publicKey = Program.GetPublicKey(@"sign.snk");

            Assert.AreEqual(publicKey, PublickToken);
        }

        [Test]
        public void Should_Get_CurrentDirrectory()
        {
            var currentDir = Program.GetCurrentDirectory(new [] {@"/dir:.\packages"});

            Assert.IsNotNull(currentDir);
        }

        [Test]
        public void Should_Not_Work_CurrentDirrectory()
        {
            var currentDir = Program.GetCurrentDirectory(new[] { @"in:.\pack" });

            Assert.IsNull(currentDir);
        }

        [Test]
        public void Should_Get_Files()
        {
            var inputFiles = GetInputFiles();

            Assert.AreEqual(inputFiles.Length, 3);
        }

        private static string[] GetInputFiles()
        {
            var inputFiles = Program.GetInputFiles(Path.Combine(Environment.CurrentDirectory, @"packages"), new[]
            {
                @"/in:FluentValidation.+;RestSharp.+"
            });
            return inputFiles
                .Where(x => !x.Contains(@".signed."))
                .ToArray();
        }

        [Test]
        public void Should_Get_Null_Assembly_Token()
        {
            var signedAssembly = Path.Combine(Environment.CurrentDirectory, @"packages", @"RestSharp.105.2.3", @"RestSharp-signed.dll");
            var publicKey = Program.GetAssemblyToken(signedAssembly).ToArray();

            Assert.IsNotNull(publicKey);
            var publicToken = publicKey.Take(8);
            var asString = string.Join(@" ", publicToken.Select(x => x.ToString(@"X2").ToUpper()));
            Assert.AreEqual(asString, PublickToken);
        }

        [Test]
        public void Should_Get_Assembly_Token()
        {
            var inputFiles = GetInputFiles();
            var tokens = inputFiles.Select(x => new
            {
                file = new FileInfo(x),
                token = Program.GetAssemblyToken(x)
            }).ToArray();

            Assert.AreEqual(inputFiles.Length, 3);
            Assert.AreEqual(tokens.Count(x => x.token == null && !x.file.Name.Contains(@"signed")), 2);
        }

        [Test]
        public void Should_Make_IL()
        {
            var inputFiles = GetInputFiles();
            var ilPaths = inputFiles.Select(Program.MakeIL).ToArray();

            Assert.AreEqual(inputFiles.Length, 3);
            Assert.IsTrue(ilPaths.All(File.Exists));
        }

        [Test]
        public void Should_Fix_IL()
        {
            var inputFiles = GetInputFiles();
            var snkPath = Path.Combine(Environment.CurrentDirectory, @"sign.snk");
            var token = Program.GetPublicKey(snkPath);
            var noValidFiles = inputFiles.Where(x => Program.GetAssemblyToken(x) == null).ToArray();
            var refsNames = Program.GetRefsNames(inputFiles);
            var ilPaths = noValidFiles
                .Select(Program.MakeIL)
                .Select(x => Program.FixExternalLinks(x, refsNames, token))
                .ToArray();
            var result = ilPaths.SelectMany(x => Program.Compile(x, snkPath, path => path.Replace(@".dll", @".signed.dll"))).ToArray();

            Assert.IsTrue(result.All(x => Program.GetAssemblyToken(x) != null));
            Assert.AreEqual(inputFiles.Length, 3);
            Assert.AreEqual(noValidFiles.Length, 2);
            //test references
            //Assert.IsTrue(ilPaths.Any(x => File.ReadAllText(x).Contains($@".publickeytoken = ( {PublickToken} )")));
        }

        [Test]
        [ExpectedException(typeof(FileNotFoundException))]
        public void Should_Not_Work_Get_File_Info_Key()
        {
            Program.GetKeyFile(new[] { @"/key:sign-not-exist.snk" });
        }
    }
}
