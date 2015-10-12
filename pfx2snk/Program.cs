namespace pfx2snk
{
    using System;
    using System.IO;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;

    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine("\n\tusage pattern:\npfx2snk my.pfx password my.snk\nor\nusage pattern:\npfx2snk my.pfx my.snk\n");
                return;
            }
            string pfx, password = string.Empty, snk;
            if (args.Length > 2)
            {
                pfx = args[0];
                password = args[1];
                snk = args[2];
            }else {
                pfx = args[0];
                snk = args[1];
            }
            Console.WriteLine($"\n\t{pfx} {password} {snk}\n");
            var cert = new X509Certificate2(pfx, password,
                X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
            var provider = (RSACryptoServiceProvider)cert.PrivateKey;

            var array = provider.ExportCspBlob(!provider.PublicOnly);
            using (var fs = new FileStream(snk, FileMode.Create, FileAccess.Write))
            {
                fs.Write(array, 0, array.Length);
            }
        }
    }
}
