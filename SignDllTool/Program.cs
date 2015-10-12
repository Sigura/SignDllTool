namespace SignDllTool
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.IO;
    using System.Linq;
    using System.Reflection;
    using System.Security.Cryptography;
    using System.Text.RegularExpressions;
    using Microsoft.Build.Utilities;

    internal static class Program
    {
        private const string Help = "\n" +
            "Samples of usage:\n\n" +
            "\tSignDllTool /dir:packages /in:RestSharp[\\.\\d]+\\\\lib\\\\net4[\\d]*\\\\;MongoDB\\.Bson;DotNetZip /key:sign.snk\n\n" +
            "where:\n\n" +
            "\t/dir:RootDirectoryOfDlls - root directory where app will search dlls\n" +
            "\t/in:Regex;For;Resolve;Path;Of;Dll;Separated;By;Semicolon - regular expression separated by ; for resolve path to dlls\n" +
            "\t/key:PathToSnkKey - path to unprotected snk key file !with private key! please see https://github.com/aarnott/pfx2Snk\n\n" +
            "pre requirements: Visual Studio or Windows SDK needed\n"+
            "http://www.microsoft.com/en-us/download/details.aspx?id=8442\n";
        const string KeyPattern = @"/key:([^ ]+)";
        const string InputFilesPattern = @"/in:([^ ]+)";
        const string CurrentDirectoryPattern = @"/dir:([^ ]+)";

        /// <summary>
        /// Solution based on article:
        /// http://buffered.io/posts/net-fu-signing-an-unsigned-assembly-without-delay-signing/
        /// </summary>
        /// <param name="args"></param>
        /// <exception cref="IOException">An I/O error occurred. </exception>
        /// <exception cref="DirectoryNotFoundException">Attempted to set a local path that cannot be found.</exception>
        /// <exception cref="PathTooLongException">The specified path, file name, or both exceed the system-defined maximum length. For example, on Windows-based platforms, paths must be less than 248 characters, and file names must be less than 260 characters. </exception>
        /// <exception cref="NotSupportedException"><paramref name="args" /> contains a colon (":") that is not part of a volume identifier (for example, "c:\"). </exception>
        /// <exception cref="FileNotFoundException">Input files not found</exception>
        /// <exception cref="UnauthorizedAccessException">Access to <paramref name="args" /> is denied. </exception>
        internal static void Main(string[] args)
        {

            if (WrongArguments(args))
            {
                Console.WriteLine(Help);
                return;
            }

            var currentDirectory = GetCurrentDirectory(args) ?? Environment.CurrentDirectory;
            var keyFileInfo = GetKeyFile(args);
            var token = GetPublicKey(keyFileInfo.FullName);
            var inputFiles = GetInputFiles(currentDirectory, args);
            var refsNames = GetRefsNames(inputFiles);
            var filesForSign = inputFiles.Where(x => GetAssemblyToken(x) == null).ToArray();
            var ilFiles = filesForSign.Select(MakeIL).ToArray();
            // ReSharper disable once UnusedVariable
            var ilFixedFiles = ilFiles.Select(x => FixExternalLinks(x, refsNames, token)).ToArray();
            var compiledFiles = ilFiles.SelectMany(x => Compile(x, keyFileInfo.FullName)).ToArray();
            var signedFilesMessage = compiledFiles.Any() ? $"\n\t* {string.Join("\n\t* ", compiledFiles)}" : "\tnot found or all completed with errors";

            Console.WriteLine($"token: {token} from file: {keyFileInfo.FullName}\nsigned dlls: {signedFilesMessage}");
        }

        /// <exception cref="ArgumentNullException"><paramref name="inputFiles" /> is null. </exception>
        /// <exception cref="SecurityException">The caller does not have the required permission. </exception>
        /// <exception cref="ArgumentException">The file name is empty, contains only white spaces, or contains invalid characters. </exception>
        /// <exception cref="UnauthorizedAccessException">Access to <paramref name="inputFiles" /> is denied. </exception>
        /// <exception cref="PathTooLongException">The specified path, file name, or both exceed the system-defined maximum length. For example, on Windows-based platforms, paths must be less than 248 characters, and file names must be less than 260 characters. </exception>
        internal static string[] GetRefsNames(string[] inputFiles)
        {
            var refsNames = inputFiles
                .Select(x => new FileInfo(x))
                .Select(x => x.Name.Length > x.Extension.Length ? x.Name.Substring(0, x.Name.Length - x.Extension.Length) : string.Empty)
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .ToArray();
            return refsNames;
        }

        internal static string GetCurrentDirectory(IEnumerable<string> args)
        {
            var result = args.FirstOrDefault(x => Regex.IsMatch(x, CurrentDirectoryPattern))?.Substring(5).Trim();

            if (result == null)
                return null;

            if (Directory.Exists(result))
            {
                return Path.GetFullPath(result);
            }

            result = Path.GetFullPath(Path.Combine(Environment.CurrentDirectory, result));

            return Directory.Exists(result) ? result : null;
        }

        /// <exception cref="IOException">An I/O error occurred. </exception>
        internal static string[] Compile(string ilFile, string pathToSnk, Func<string, string> newNameBuilder = null)
        {
            try
            {
                const string name = @"ilasm.exe";
                var ilasm = ToolLocationHelper.GetPathToDotNetFrameworkFile(name, TargetDotNetFrameworkVersion.VersionLatest);

                if (string.IsNullOrEmpty(ilasm) || !File.Exists(ilasm))
                    throw new FileNotFoundException($"{name} not exists. Please install Visual Studio or Windows SDK\nhttp://www.microsoft.com/en-us/download/details.aspx?id=8442\n");

                var outPath = Regex.Replace(ilFile, @"\.il(\.|$)", @"$1");
                if (File.Exists(outPath))
                {
                    var bakName = $"{outPath}.bak";
                    RemoveFileIfExists(bakName);
                    File.Copy(outPath, bakName);
                }
                var tmpName = outPath.Replace(@".dll", @".signed.dll");
                RemoveFileIfExists(tmpName);
                if (newNameBuilder != null)
                    outPath = newNameBuilder(outPath);
                var process = MakeBackgroundProcess(ilasm, $"{ilFile} /dll /key={pathToSnk} /output={tmpName} /QUIET");
                RunProcess(process, name);
                if (tmpName != outPath)
                {
                    RemoveFileIfExists(outPath);
                    File.Move(tmpName, outPath);
                }

                return new []{outPath};
            }
            catch (Exception e)
            {
                Console.WriteLine($@"Compile {ilFile} failed: {e}");
            }
            return new string[0];
        }

        private static void RemoveFileIfExists(string bakName)
        {
            if (File.Exists(bakName))
            {
                File.Delete(bakName);
            }
        }

        private static void RunProcess(Process process, string name)
        {
            try
            {
                var error = string.Empty;
                process.ErrorDataReceived += (sender, args) => { error = args.Data; };
                var start = process.Start();
                var readToEnd = process.StandardOutput.ReadToEnd();
                if (start)
                    process.WaitForExit(5000);

                if (!process.HasExited)
                {
                    process.CloseMainWindow();
                    process.Kill();
                }
                process.Dispose();

                if (!start || !string.IsNullOrWhiteSpace(error))
                {
                    throw new ApplicationException($@"{name} do not started or return error {error}");
                }

                if (readToEnd.ToUpper().Contains(@"FAILURE") || readToEnd.ToUpper().Contains(@"error"))
                {
                    throw new ApplicationException($"return error\n{readToEnd}");
                }
            }
            catch (InvalidOperationException e)
            {
                throw new FileNotFoundException($"{process.StartInfo.FileName} {process.StartInfo.Arguments} could not run. Please install Visual Studio or Windows SDK\nhttp://www.microsoft.com/en-us/download/details.aspx?id=8442\n", e);
            }
        }

        /// <exception cref="DirectoryNotFoundException">The specified path is invalid (for example, it is on an unmapped drive). </exception>
        /// <exception cref="IOException">An I/O error occurred while opening the file. </exception>
        /// <exception cref="PathTooLongException">The specified path, file name, or both exceed the system-defined maximum length. For example, on Windows-based platforms, paths must be less than 248 characters, and file names must be less than 260 characters. </exception>
        /// <exception cref="NotSupportedException"><paramref name="ilFile" /> is in an invalid format. </exception>
        /// <exception cref="UnauthorizedAccessException"><paramref name="ilFile" /> specified a file that is read-only.-or- This operation is not supported on the current platform.-or- <paramref name="ilFile" /> specified a directory.-or- The caller does not have the required permission. </exception>
        /// <exception cref="FileNotFoundException">The file specified in <paramref name="ilFile" /> was not found. </exception>
        /// <exception cref="SecurityException">The caller does not have the required permission. </exception>
        internal static string FixExternalLinks(string ilFile, string[] refNames, string token)
        {
            var readAllText = File.ReadAllText(ilFile);
            foreach (var name in refNames)
            {
                var regex = new Regex($@"^.assembly extern {name}(?<endOfLine>\s+)\{{(?<startEndOfLine>\s+)\.ver (?<version>\d+:\d+:\d+:\d+)(?<endEndOfLine>\s+)}}", RegexOptions.IgnoreCase | RegexOptions.Multiline | RegexOptions.ExplicitCapture);

                readAllText = regex.Replace(readAllText, $".assembly extern {name}${{endOfLine}}{{${{startEndOfLine}}.publickeytoken = ( {token} )\n  .ver ${{version}}${{endEndOfLine}}}}");
            }
            File.WriteAllText(ilFile, readAllText);
            return ilFile;
        }

        internal static Process MakeBackgroundProcess(string command, string arguments)
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = command,
                Arguments = arguments,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                WindowStyle = ProcessWindowStyle.Hidden,
                CreateNoWindow = true
            };

            var process = new Process
            {
                StartInfo = startInfo,
                EnableRaisingEvents = true,
            };

            return process;
        }

        /// <exception cref="DirectoryNotFoundException">The specified path is invalid (for example, it is on an unmapped drive). </exception>
        /// <exception cref="IOException">The specified file is in use. -or-There is an open handle on the file, and the operating system is Windows XP or earlier. This open handle can result from enumerating directories and files. For more information, see How to: Enumerate Directories and Files.</exception>
        /// <exception cref="UnauthorizedAccessException">The caller does not have the required permission.-or- The file is an executable file that is in use.-or- <paramref name="path" /> is a directory.-or- <paramref name="path" /> specified a read-only file. </exception>
        /// <exception cref="NotSupportedException"><paramref name="path" /> is in an invalid format. </exception>
        /// <exception cref="PathTooLongException">The specified path, file name, or both exceed the system-defined maximum length. For example, on Windows-based platforms, paths must be less than 248 characters, and file names must be less than 260 characters. </exception>
        internal static string MakeIL(string path)
        {
            const string name = @"ildasm.exe";
            var ildasm = ToolLocationHelper.GetPathToDotNetFrameworkSdkFile(name, TargetDotNetFrameworkVersion.VersionLatest);
            var outPath = $@"{path}.il";

            if (File.Exists(outPath))
                File.Delete(outPath);

            var toolDir = AssemblyDirectory;
            ildasm = !string.IsNullOrEmpty(ildasm) && File.Exists(ildasm) ? ildasm : Path.Combine(toolDir, name);

            if (!File.Exists(ildasm))
                throw new FileNotFoundException($"{name} not exists.\n{ildasm} not found.\nPlease install Windows SDK or Visual Studio\nhttp://www.microsoft.com/en-us/download/details.aspx?id=8442\n");


            var process = MakeBackgroundProcess(ildasm, $"{path} /out:{outPath}");
            RunProcess(process, name);

            return outPath;
        }

        internal static string AssemblyDirectory
        {
            get
            {
                var codeBase = Assembly.GetExecutingAssembly().CodeBase;
                var uri = new UriBuilder(codeBase);
                var path = Uri.UnescapeDataString(uri.Path);
                return Path.GetDirectoryName(path);
            }
        }

        /// <exception cref="FileNotFoundException">Input files not found</exception>
        internal static string[] GetInputFiles(string currentDirectory, IEnumerable<string> args)
        {
            var param = args.First(x => Regex.IsMatch(x, InputFilesPattern)).Substring(4).Trim();
            if (string.IsNullOrWhiteSpace(param))
                throw new FileNotFoundException($"/in:files not exists\n\n{Help}");
            var files = param.Split(';').ToArray();
            var allFiles = Directory.GetFiles(currentDirectory, @"*.dll", SearchOption.AllDirectories)
                .SelectMany(x => MatchFiles(x, files))
                .ToArray();
            var corruptedFiles = allFiles
                .Where(IsCorruptFile)
                .ToArray();

            if (corruptedFiles.Any())
            {
                throw new FileNotFoundException($"/in:files not found:{string.Join(";\n", corruptedFiles)}\n\n{Help}");
            }
            return allFiles;
        }

        private static IEnumerable<string> MatchFiles(string file, string[] patterns)
        {
            if (patterns.Any(x => x == file) || patterns.Any(x => new Regex(x).IsMatch(file)))
                return new [] { file };

            return new string [0];
        }

        /// <exception cref="ArgumentNullException"><paramref name="assemblyPath"/> is <see langword="null" />.</exception>
        /// <exception cref="Exception">An error occurred during the unload process.</exception>
        internal static byte[] GetAssemblyToken(string assemblyPath)
        {
            if (assemblyPath == null)
                throw new ArgumentNullException(nameof(assemblyPath));

            try
            {
                var activator = typeof(ApplicationProxy);
                var domainSetup = new AppDomainSetup
                {
                    PrivateBinPath = assemblyPath,
                    ApplicationName = @"Temp",
                    ApplicationBase = AppDomain.CurrentDomain.BaseDirectory
                };
                var dom = AppDomain.CreateDomain($"AppDomin-for-{assemblyPath}", null, domainSetup);
                var proxy = (ApplicationProxy)dom.CreateInstanceAndUnwrap( Assembly.GetAssembly(activator).FullName, activator.ToString());
                var asmToken = proxy.GetPublicKeyToken(assemblyPath);
                var token = asmToken.Any() ? asmToken : null;
                AppDomain.Unload(dom);

                GC.Collect();
                GC.WaitForPendingFinalizers();
                GC.Collect();

                return token;
            }
            catch(CannotUnloadAppDomainException)
            {
                return null;
            }
            catch (FileLoadException)
            {
                return null;
            }
            catch (MethodAccessException)
            {
                return null;
            }
            catch (TypeLoadException)
            {
                return null;
            }
            catch (MissingMethodException)
            {
                return null;
            }
            catch (AppDomainUnloadedException)
            {
                return null;
            }
            catch (FileNotFoundException)
            {
                return null;
            }
            catch (BadImageFormatException)
            {
                return null;
            }
        }

        internal class ApplicationProxy : MarshalByRefObject
        {
            public byte[] GetPublicKeyToken(string assemblyPath)
            {
                var assembly = Assembly.Load(new AssemblyName
                {
                    CodeBase = assemblyPath
                });
                return assembly.GetName().GetPublicKeyToken();
            }
        }

        internal static bool IsCorruptFile(string path)
        {
            var fullName = GetFullName(path);

            return !File.Exists(fullName);
        }

        /// <exception cref="SecurityException">The caller does not have the appropriate permission.</exception>
        /// <exception cref="DirectoryNotFoundException">Attempted to set a local path that cannot be found.</exception>
        /// <exception cref="IOException">An I/O error occurred.</exception>
        internal static string GetFullName(string path)
        {
            var currentDirectory = Environment.CurrentDirectory;
            return File.Exists(path) ? path : Path.GetFullPath(Path.Combine(currentDirectory, path));
        }

        internal static bool WrongArguments(string[] args)
        {
            var pre = !args.Any() || args.Contains(@"/h") || args.Contains(@"-help") || args.Contains(@"--help") ||
                !args.Any(x => Regex.IsMatch(x, KeyPattern)) ||
                !args.Any(x => Regex.IsMatch(x, InputFilesPattern));

            return pre;
        }

        /// <exception cref="PathTooLongException">The specified path, file name, or both exceed the system-defined maximum length. For example, on Windows-based platforms, paths must be less than 248 characters, and file names must be less than 260 characters. </exception>
        /// <exception cref="NotSupportedException"><paramref name="args" /> contains a colon (":") that is not part of a volume identifier (for example, "c:\"). </exception>
        /// <exception cref="SecurityException">The caller does not have the required permissions. </exception>
        /// <exception cref="FileNotFoundException">Condition.</exception>
        /// <exception cref="UnauthorizedAccessException">Access to <paramref name="args" /> is denied. </exception>
        internal static FileInfo GetKeyFile(IEnumerable<string> args)
        {
            var key = args.First(x => Regex.IsMatch(x, KeyPattern)).Substring(5).Trim();
            var pathToKeyFile = Path.GetFullPath(key);
            if (string.IsNullOrWhiteSpace(key) || !File.Exists(pathToKeyFile))
                throw new FileNotFoundException($"/key:file not exists {pathToKeyFile}\n\n{Help}");

            return new FileInfo(key);
        }

        /// <exception cref="DirectoryNotFoundException">The specified path is invalid, such as being on an unmapped drive. </exception>
        /// <exception cref="SecurityException">The caller does not have the required permission. </exception>
        /// <exception cref="IOException">An I/O error, such as specifying FileMode.CreateNew when the file specified by <paramref name="fileName" /> already exists, occurred. -or-The stream has been closed.</exception>
        internal static string GetPublicKey(string fileName, string password = null)
        {
            using (var stream = new FileStream(fileName, FileMode.Open, FileAccess.Read))
            {
                var pair = new StrongNameKeyPair(stream);
                var hash = new SHA1CryptoServiceProvider();
                var publicKey = hash.ComputeHash(pair.PublicKey);
                Array.Reverse(publicKey);
                var publicKeyToken = publicKey
                    .Take(8)
                    .Select(x => x.ToString("X2").ToUpper())
                    .ToArray();

                return string.Join(@" ", publicKeyToken);
            }
        }
    }
}
