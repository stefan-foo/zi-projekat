using Google;
using Grpc.Core;
using Grpc.Net.Client;
using System.Threading.Tasks;
using Cryptography.ServiceHost;
using Cryptography.Client.Utils;
using static Cryptography.ServiceHost.Cryptography;

using (var channel = GrpcChannel.ForAddress("https://localhost:7135"))
{
    var client = new CryptographyLib(new CryptographyClient(channel));

    string originalHash = await client.SHA1HashFile("./Res/Input/file.txt");
    Console.WriteLine($"./Res/Input/file.txt SHA1: {originalHash}");
    string fscTestHash = await client.SHA1HashFile("./Res/Input/fsctest.txt");
    Console.WriteLine($"./Res/Input/fsctest.txt SHA1: {fscTestHash}");
    string bmpHash = await client.SHA1HashFile("./Res/Input/bmpTest.bmp");
    Console.WriteLine($"./Res/Input/bmpTest.bmp SHA1: {bmpHash}");

    await client.OTPEncrypt("./Res/Input/file.txt", "./Res/Input/OTPKey.txt", "./Res/Generated/OTPEncrypted.txt");
    await client.OTPDecrypt("./Res/Generated/OTPEncrypted.txt", "./Res/Input/OTPKey.txt", "./Res/Generated/OTPDecrypted.txt");
    bool isValid = await client.SHA1VerifyFileHash("./Res/Generated/OTPDecrypted.txt", originalHash);
    Console.WriteLine("OneTimePad valid: " + isValid);

    await client.XXTEAEncrypt("./Res/Input/file.txt", "./Res/Generated/XXTEAEncrypted.txt", "xxteakeytestteak");
    await client.XXTEADecrypt("./Res/Generated/XXTEAEncrypted.txt", "./Res/Generated/XXTEADecrypted.txt", "xxteakeytestteak");
    isValid = await client.SHA1VerifyFileHash("./Res/Generated/XXTEADecrypted.txt", originalHash);
    Console.WriteLine("XXTEA valid: " + isValid);

    await client.FSCEncrypt("./Res/Input/fsctest.txt", "./Res/Generated/fscEncrypted.txt", "gzptfoihmuwdrcnykeqaxvsbl", "mfnbdcrhsaxyogvituewlqzkp");
    await client.FSCDecrypt("./Res/Generated/fscEncrypted.txt", "./Res/Generated/fscDecrypted.txt", "gzptfoihmuwdrcnykeqaxvsbl", "mfnbdcrhsaxyogvituewlqzkp");
    isValid = await client.SHA1VerifyFileHash("./Res/Generated/fscDecrypted.txt", fscTestHash);
    Console.WriteLine("FSC valid: " + isValid);

    await client.OFBEncrypt("./Res/Input/file.txt", "./Res/Input/OFBIv.txt", "./Res/Generated/OFBEncrypted.txt", "xxteakeytestteak");
    await client.OFBDecrypt("./Res/Generated/OFBEncrypted.txt", "./Res/Input/OFBIv.txt", "./Res/Generated/OFBDecrypted.txt", "xxteakeytestteak");
    isValid = await client.SHA1VerifyFileHash("./Res/Generated/OFBDecrypted.txt", originalHash);
    Console.WriteLine("OFB valid: " + isValid);

    await client.EncryptBMP("./Res/Input/bmpTest.bmp", "./Res/Generated/bmpEncrypted.bmp", "./Res/Generated/bmpKey.txt");
    await client.DecryptBMP("./Res/Generated/bmpEncrypted.bmp", "./Res/Generated/bmpKey.txt", "./Res/Generated/bmpDecrypted.bmp");
    isValid = await client.SHA1VerifyFileHash("./Res/Generated/bmpDecrypted.bmp", bmpHash);
    Console.WriteLine("BMP valid: " + isValid);

    Console.WriteLine("Press any key to continue...");
    Console.ReadLine();
}

