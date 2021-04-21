import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.Cipher;

public abstract class SP1 {
	private static byte[] nonce = new byte[32];
	public static void main(String[] args) {

    	int port = 4323;
    	if (args.length > 0) port = Integer.parseInt(args[0]);

		ServerSocket welcomeSocket = null;
		Socket connectionSocket = null;
		DataOutputStream toClient = null;
		DataInputStream fromClient = null;

		FileOutputStream fileOutputStream = null;
		BufferedOutputStream bufferedFileOutputStream = null;

		try {
			PrivateKey privateKey = PrivateKeyReader("private_key.der");
			welcomeSocket = new ServerSocket(port);
			connectionSocket = welcomeSocket.accept();
			fromClient = new DataInputStream(connectionSocket.getInputStream());
			toClient = new DataOutputStream(connectionSocket.getOutputStream());

			// while (!connectionSocket.isConnected()) {
			while (!connectionSocket.isClosed()) {

				int packetType = fromClient.readInt();
				
				// Indicate start of AP
				if (packetType == 2) {
					System.out.println("Starting Authentication Protocol with client");
					InputStream fis = new FileInputStream("certificate_1004238.crt");
					CertificateFactory cf = CertificateFactory.getInstance("X.509");
					X509Certificate serverCert =(X509Certificate) cf.generateCertificate(fis);
					byte[] serverCertEncoded = serverCert.getEncoded();
					// Must use read fully!
					// See: https://stackoverflow.com/questions/25897627/datainputstream-read-vs-datainputstream-readfully
					// PublicKey key = serverCert.getPublicKey();

					// get nonce from client
					System.out.println("Retrieve nonce from client");
					fromClient.read(nonce);
					Cipher cipherSettings = Cipher.getInstance("RSA/ECB/PKCS1Padding");	// encrypt nonce for client
					cipherSettings.init(Cipher.ENCRYPT_MODE, privateKey);
					byte[] encryptedNonce = cipherSettings.doFinal(nonce);

					// send nonce to client
					System.out.println("Sent encrypted nonce to client");
					toClient.write(encryptedNonce);
					toClient.flush();

					// send cert to client
					System.out.println("Sending the encoded cert to client");
					// toClient.writeInt(serverCertEncoded.length);
					toClient.write(serverCertEncoded);
					toClient.flush();

					/////////// AP done
				} 


				// If the packet is for transferring the filename
				if (packetType == 0) {

					System.out.println("Receiving file...");

					int numBytes = fromClient.readInt();
					byte [] filename = new byte[numBytes];
					fromClient.readFully(filename, 0, numBytes);

					fileOutputStream = new FileOutputStream("recv_" + new String(filename, 0, numBytes));
					bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);

				// If the packet is for transferring a chunk of the file
				} else if (packetType == 1) {

					int numBytes = fromClient.readInt();
					int forEncryptNumBytes = fromClient.readInt();
					byte [] block = new byte[forEncryptNumBytes];
					fromClient.readFully(block, 0, forEncryptNumBytes);
					// decrupt using private key
					Cipher decipherSettings = Cipher.getInstance("RSA/ECB/PKCS1Padding");
					decipherSettings.init(Cipher.DECRYPT_MODE, privateKey);
					byte[] decryptBlock = decipherSettings.doFinal(block);

					if (numBytes > 0)
						// bufferedFileOutputStream.write(block, 0, numBytes);
						bufferedFileOutputStream.write(decryptBlock, 0, numBytes);

					if (numBytes < 117) {
						// System.out.println("Closing connection...");
						System.out.println("Received the file");

						if (bufferedFileOutputStream != null) bufferedFileOutputStream.close();
						if (bufferedFileOutputStream != null) fileOutputStream.close();
						// fromClient.close();
						// toClient.close();
						// connectionSocket.close();
					}
				}
				
				if (packetType == 4) {
					System.out.println("Closing connection...");
					fromClient.close();
					toClient.close();
					connectionSocket.close();
				}

			}
		} catch (Exception e) {e.printStackTrace();}

	}
	public static PrivateKey PrivateKeyReader(String filename) throws Exception {
		byte[] keyBytes = Files.readAllBytes(Paths.get(filename));
	
		PKCS8EncodedKeySpec spec =new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePrivate(spec);
	}

}
