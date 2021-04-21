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
    	// if (args.length > 2) port = Integer.parseInt(args[2]);

		int numByte = 0;

		Socket clientSocket = null;

        DataOutputStream toServer = null;
        DataInputStream fromServer = null;

    	FileInputStream fileInputStm = null;
        BufferedInputStream bufferedFileInputStm = null;

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
			InputStream fInput = new FileInputStream("cacsertificate.crt");
			CertificateFactory cFactory = CertificateFactory.getInstance("X.509");
			X509Certificate caCert4Checking =(X509Certificate) cFactory.generateCertificate(fInput);
			PublicKey key = caCert4Checking.getPublicKey();

			// Generate nonce
			System.out.println("Retrieve nonce");
			SecureRandom rand = new SecureRandom();
			rand.nextBytes(nonce);
			System.out.println("Sending to server now");
			toServer.write(nonce);

			// Get encrypted nonce from server
			System.out.println("Getting the encrypted nonce from server side");
			fromServer.read(encryptedNonce);
			// System.out.println("Getting the encoded cert");
			X509Certificate CertFromServer = (X509Certificate) cFactory.generateCertificate(fromServer);

			// check the cert using my public key
			System.out.println("Verifying the cert from server");
			CertFromServer.checkValidity();
			CertFromServer.verify(key);

			// Verify that i'm the one who created the nonce using server's public key
			PublicKey serverKey = CertFromServer.getPublicKey();	// getting server's public key
			Cipher settingForDecipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			settingForDecipher.init(Cipher.DECRYPT_MODE, serverKey);
			byte[] decryptedNonce = settingForDecipher.doFinal(encryptedNonce);

			if (Arrays.equals( nonce, decryptedNonce )) {
				System.out.println("Server is verified already....move on");
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
				fileInputStm = new FileInputStream(filename);
				bufferedFileInputStm = new BufferedInputStream(fileInputStm);

				byte [] fromFileBuffer = new byte[117];

				// Now, send file
				for (boolean finishedFile = false; !finishedFile;) {
					numByte = bufferedFileInputStm.read(fromFileBuffer);
					finishedFile = numByte < 117;

					// encrypt using Public key for CP1
					Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
					cipher.init(Cipher.ENCRYPT_MODE, publickey);
					byte[] encryptFromFileBuffer = cipher.doFinal(fromFileBuffer);
					int encryptLengthBytes = encryptFromFileBuffer.length;

					toServer.writeInt(1);
					toServer.writeInt(numByte);
					toServer.writeInt(encryptLengthBytes);
					toServer.write(encryptFromFileBuffer);
					toServer.flush();
				}

				System.out.println("Finished sending " + filename);

				int argsLength = args.length - 1; 
				if (i == argsLength) {
					// indicate to server it is the end
					toServer.writeInt(4);
					bufferedFileInputStm.close();
					fileInputStm.close();
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
