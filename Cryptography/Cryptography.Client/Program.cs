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

    string originalHash = await client.SHA1HashFile("./Res/file.txt");

    await client.OneTimePadEncrypt("./Res/file.txt", "./Res/onetimepadkey.txt", "./Res/OTPEncrypted.txt");
    await client.OneTimePadDecrypt("./Res/OTPEncrypted.txt", "./Res/onetimepadkey.txt", "./Res/OTPDecrypted.txt");
    bool isValid = await client.SHA1VerifyFileHash("./Res/OTPDecrypted.txt", originalHash);
    Console.WriteLine("OneTimePad: " + isValid);

    await client.XXTEAEncrypt("./Res/file.txt", "./Res/XXTEAEncrypted.txt", "xxteakeytestteak");
    await client.XXTEADecrypt("./Res/XXTEAEncrypted.txt", "./Res/XXTEADecrypted.txt", "xxteakeytestteak");
    isValid = await client.SHA1VerifyFileHash("./Res/XXTEADecrypted.txt", originalHash);
    Console.WriteLine("XXTEA: " + isValid);

    //await client.FSCEncrypt("./Res/fsctest.txt", "./Res/fsctest-encrypted.txt", "gzptfoihmuwdrcnykeqaxvsbl", "mfnbdcrhsaxyogvituewlqzkp");
    //await client.FSCDecrypt("./Res/fsctest-encrypted.txt", "./Res/fsctest-decrypted.txt", "gzptfoihmuwdrcnykeqaxvsbl", "mfnbdcrhsaxyogvituewlqzkp");
    await client.OFBEncrypt("./Res/file.txt", "./Res/vi.txt", "./Res/OFBEncrypted.txt", "xxteakeytestteak");
    await client.OFBDecrypt("./Res/OFBEncrypted.txt", "./Res/vi.txt", "./Res/OFBDecrypted.txt", "xxteakeytestteak");
    isValid = await client.SHA1VerifyFileHash("./Res/OFBDecrypted.txt", originalHash);
    Console.WriteLine("OFB: " + isValid);

    var bmpHash = await client.SHA1HashFile("./Res/bmpTest.bmp");
    await client.EncryptBMP("./Res/bmpTest.bmp", "./Res/bmpEncrypted.bmp", "./Res/bmpKey.txt");
    await client.DecryptBMP("./Res/bmpEncrypted.bmp", "./Res/bmpKey.txt", "./Res/bmpDecrypted.bmp");
    isValid = await client.SHA1VerifyFileHash("./Res/bmpDecrypted.bmp", bmpHash);
    Console.WriteLine("BMP: " + isValid);

    Console.ReadLine();
}

