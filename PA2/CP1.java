import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.Cipher;

public abstract class CP1 {
	private static byte[] nonce = new byte[32];
    private static byte[] encryptedNonce = new byte[128];
	public static void main(String[] args) {

    	String filename;
    	// if (args.length > 0) filename = args[0];

    	String serverAddress = "localhost";
    	// if (args.length > 1) filename = args[1];

    	int port = 4323;
    	if (args.length > 2) port = Integer.parseInt(args[2]);

		int numBytes = 0;

		Socket clientSocket = null;

        DataOutputStream toServer = null;
        DataInputStream fromServer = null;

    	FileInputStream fileInputStream = null;
        BufferedInputStream bufferedFileInputStream = null;

		long timeStarted = System.nanoTime();

		try {
			PublicKey publickey = PublicKeyReader("public_key.der");
			System.out.println("Establishing connection to server...");

			// Connect to server and get the input and output streams
			clientSocket = new Socket(serverAddress, port);
			toServer = new DataOutputStream(clientSocket.getOutputStream());
			fromServer = new DataInputStream(clientSocket.getInputStream());

			// to indicate start of AP
			toServer.writeInt(2);

			// Start AP
			InputStream fis = new FileInputStream("cacsertificate.crt");
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			X509Certificate CAcert =(X509Certificate) cf.generateCertificate(fis);
			PublicKey key = CAcert.getPublicKey();

			// Generate nonce
			System.out.println("Gen nonce");
			SecureRandom random = new SecureRandom();
			random.nextBytes(nonce);
			System.out.println("Sent to server");
			toServer.write(nonce);

			// Get encrypted nonce from server
			System.out.println("Getting the encrypted nonce from server side");
			fromServer.read(encryptedNonce);
			System.out.println("Getting the encoded cert");
			X509Certificate ServerCert = (X509Certificate) cf.generateCertificate(fromServer);

			// check the cert using my public key
			System.out.println("Verifying the cert from server");
			ServerCert.checkValidity();
			ServerCert.verify(key);

			// Verify that i'm the one who created the nonce using server's public key
			// getting server's public key
			PublicKey serverKey = ServerCert.getPublicKey();
			Cipher decipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			decipher.init(Cipher.DECRYPT_MODE, serverKey);
			byte[] decryptNonce = decipher.doFinal(encryptedNonce);

			if (Arrays.equals(nonce, decryptNonce)) {
				System.out.println("Verified server");
			} else {
				// indicate in attack
				System.out.println("Server verification failed and closing all connections...");
				toServer.writeInt(4);
				toServer.close();
				fromServer.close();
				clientSocket.close();
			}
			///////// AP end

			//////////  sending multiple files using for loop
			for (int i = 0; i < args.length; i ++) {
				System.out.println("Sending file...");
				filename = args[i];

				// Send filename
				toServer.writeInt(0);
				toServer.writeInt(filename.getBytes().length);
				toServer.write(filename.getBytes());
				toServer.flush(); // thanks prof:)

				// Open file
				fileInputStream = new FileInputStream(filename);
				bufferedFileInputStream = new BufferedInputStream(fileInputStream);

				byte [] fromFileBuffer = new byte[117];

				// Now, send file
				for (boolean fileEnded = false; !fileEnded;) {
					numBytes = bufferedFileInputStream.read(fromFileBuffer);
					fileEnded = numBytes < 117;

					// encrypt using Public key for CP1
					Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
					cipher.init(Cipher.ENCRYPT_MODE, publickey);
					byte[] encryptFromFileBuffer = cipher.doFinal(fromFileBuffer);
					int encryptLengthBytes = encryptFromFileBuffer.length;

					toServer.writeInt(1);
					toServer.writeInt(numBytes);
					toServer.writeInt(encryptLengthBytes);
					toServer.write(encryptFromFileBuffer);
					toServer.flush();
				}

				System.out.println("Finished sending " + filename);

				if (i == args.length -1) {
					// indicate to server it is the end
					toServer.writeInt(4);
					bufferedFileInputStream.close();
					fileInputStream.close();
				}

				// bufferedFileInputStream.close();
				// fileInputStream.close();
			}
			System.out.println("Closing connection...");

		} catch (Exception e) {e.printStackTrace();}

		long timeTaken = System.nanoTime() - timeStarted;
		System.out.println("Program took: " + timeTaken/1000000.0 + "ms to run");
	}
	public static PublicKey PublicKeyReader(String filename) throws Exception {
		byte[] keyBytes = Files.readAllBytes(Paths.get(filename));
	
		X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePublic(spec);
	}
}
