import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.*;
import org.apache.commons.codec.binary.Base64;

public class bob {

	public static void main(String[] args) {
		int portNumber = Integer.parseInt(args[0]);
		ServerSocket BobSocket = null;

		bob bob = new bob();
		// byte[] message;
		String line;
		DataInputStream in;
		// DataOutputStream out;
		PrintStream out;
		// ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		Socket AliceSocket = null;

		try {
			BobSocket = new ServerSocket(portNumber);
		} catch (IOException e) {
			System.out.println(e);
		}

		try {
			/*
			 * Original Work // AliceSocket = BobSocket.accept(); // in = new
			 * DataInputStream(AliceSocket.getInputStream()); // // int len; //
			 * // byte[] data = new byte[1024]; // // while((len = in.read(data,
			 * 0, data.length))!=-1) // { // buffer.write(data, 0, len); // } //
			 * // buffer.flush();
			 * 
			 * //byte[] bytes in.readFully(data);
			 * 
			 * // System.out.println(buffer.toByteArray().toString());
			 * 
			 * // out = new ByteArrayOutputStream(); // message = new
			 * byte[1024]; // int length = 0; // while((length =
			 * in.read(message))!=-1) // { // out.write(message, 0, length); //
			 * }
			 * 
			 * // out.close();
			 */

			System.out
					.println("-------GENRATE Bob's PUBLIC and PRIVATE KEY-------------");
			KeyPairGenerator keyPairGenerator = KeyPairGenerator
					.getInstance("RSA");
			keyPairGenerator.initialize(1024); // 1024 used for normal
												// securities
			KeyPair keyPair = keyPairGenerator.generateKeyPair();
			PublicKey publicKey = keyPair.getPublic();
			PrivateKey privateKey = keyPair.getPrivate();
			System.out.println("Bob's Public Key - " + publicKey);
			System.out.println("Bob's Private Key - " + privateKey);

			// Pullingout parameters which makes up Key
			System.out
					.println("\n------- PULLING OUT PARAMETERS WHICH MAKES KEYPAIR----------\n");
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			RSAPublicKeySpec rsaPubKeySpec = keyFactory.getKeySpec(publicKey,
					RSAPublicKeySpec.class);
			RSAPrivateKeySpec rsaPrivKeySpec = keyFactory.getKeySpec(
					privateKey, RSAPrivateKeySpec.class);
			System.out
					.println("PubKey Modulus : " + rsaPubKeySpec.getModulus());
			System.out.println("PubKey Exponent : "
					+ rsaPubKeySpec.getPublicExponent());
			System.out.println("PrivKey Modulus : "
					+ rsaPrivKeySpec.getModulus());
			System.out.println("PrivKey Exponent : "
					+ rsaPrivKeySpec.getPrivateExponent());

			// Share public key with other so they can encrypt data and decrypt
			// thoses using private key(Don't share with Other)
			System.out
					.println("\n--------SAVING PUBLIC KEY AND PRIVATE KEY TO FILES-------\n");
			bob.saveKeys("BobPublic.key", rsaPubKeySpec.getModulus(),
					rsaPubKeySpec.getPublicExponent());
			bob.saveKeys("BobPrivate.key", rsaPrivKeySpec.getModulus(),
					rsaPrivKeySpec.getPrivateExponent());

			AliceSocket = BobSocket.accept();
			System.out.println("Bob: Accepted the socket connection from Alice.");
			in = new DataInputStream(AliceSocket.getInputStream());
			out = new PrintStream(AliceSocket.getOutputStream());
			// As long as we receive data, echo that data back to the client.
			while (true) {
				line = in.readLine();
				if (line.equals("HELLO")) {
					System.out.println("Bob: Received 'Hello' from Alice, start sending the Public Key and Signature to Alice.");
					System.out.println("Bob: Creating a signature....");
					Signature signatrue = Signature.getInstance("SHA1withRSA");
					PrivateKey CprivateKey = bob
							.readPrivateKeyFromFile("CPrivate.key");
					signatrue.initSign(CprivateKey);

					PublicKey BobPublicKey = bob
							.readPublicKeyFromFile("BobPublic.key");

					signatrue.update(BobPublicKey.getEncoded());

					byte[] BobSign = signatrue.sign();
					String BobPublicKeyToString = Base64
							.encodeBase64String(BobPublicKey.getEncoded());
					String BobSignture = Base64.encodeBase64String(BobSign);
					out.println("OK");
					out.println(BobPublicKeyToString);
					out.println(BobSignture);
				} else {
					String encryptionOfOriginalMessageInString = line;
					String encryptionOfencryptedMessageDigestInString = in
							.readLine();
					String encryptedSymmetricKeyInString = in.readLine();

					Cipher dipher = Cipher.getInstance("RSA");
					dipher.init(Cipher.DECRYPT_MODE, privateKey);
					byte[] SymmetricKey = dipher.doFinal(Base64
							.decodeBase64(encryptedSymmetricKeyInString));

					SecretKey keyFromBytes = new SecretKeySpec(SymmetricKey,
							"DESede");

					// Get the actual message received from Alice
					Cipher c = Cipher.getInstance("DESede");
					byte[] encryptedMessage = Base64
							.decodeBase64(encryptionOfOriginalMessageInString);
					String actualMessage = bob.decryptBySymmetricKey(
							encryptedMessage, keyFromBytes, c);
					System.out.println("Acutal message received from Alice: "+ actualMessage);

					// Save this message into the file
					PrintWriter writer = new PrintWriter("m.txt");
					writer.println(actualMessage);
					writer.close();

					// Decrypt the data and try to get the message digest
					byte[] encryptionOfencryptedMessageDigest = Base64
							.decodeBase64(encryptionOfencryptedMessageDigestInString);
					c.init(Cipher.DECRYPT_MODE, keyFromBytes);
					PublicKey AlicePublicKey = bob.readPublicKeyFromFile("AlicePublic.key");
					String encryptedMessageDigestInString = bob.decryptBySymmetricKey(encryptionOfencryptedMessageDigest, keyFromBytes, c);
					//System.out.println(encryptedMessageDigestInString);
					byte[] encryptedMessageDigest = Base64.decodeBase64(encryptedMessageDigestInString);
					
					String messageDigest = bob.decryptDataWithPublicKey(
							encryptedMessageDigest, "AlicePublic.key");

					// Message digest
					MessageDigest md = MessageDigest.getInstance("SHA-1");
					FileInputStream fis = new FileInputStream("m.txt");

					byte[] dataBytes = new byte[1024];

					int nread = 0;
					while ((nread = fis.read(dataBytes)) != -1) {
						md.update(dataBytes, 0, nread);
					}
					;
					byte[] mdbytes = md.digest();
					
          	        StringBuffer sb = new StringBuffer();
          	        for (int i = 0; i < mdbytes.length; i++) {
          	          sb.append(Integer.toString((mdbytes[i] & 0xff) + 0x100, 16).substring(1));
          	        }
          	        
          	        System.out.println("Message Digest: " + sb.toString());
					
					if(sb.toString().equals(messageDigest))
					{
						System.out.println("Message Digests are equal, message " + actualMessage + " is from Alice.");
					}
					fis.close();
				}
			}

		} catch (IOException e) {

		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	private static String bytes2String(byte[] bytes) {
		StringBuilder string = new StringBuilder();
		for (byte b : bytes) {
			String hexString = Integer.toHexString(0x00FF & b);
			string.append(hexString.length() == 1 ? "0" + hexString : hexString);
		}
		return string.toString();
	}

	/**
	 * Encrypt Data
	 * 
	 * @param data
	 * @throws IOException
	 */
	private byte[] encryptData(String data, String filename) throws IOException {
		System.out.println("\n----------------ENCRYPTION STARTED------------");

		System.out.println("Data Before Encryption :" + data);
		byte[] dataToEncrypt = data.getBytes();
		byte[] encryptedData = null;
		try {
			PublicKey pubKey = readPublicKeyFromFile(filename);
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, pubKey);
			encryptedData = cipher.doFinal(dataToEncrypt);
			System.out.println("Encryted Data: " + encryptedData);

		} catch (Exception e) {
			e.printStackTrace();
		}

		System.out.println("----------------ENCRYPTION COMPLETED------------");
		return encryptedData;
	}

	/**
	 * Encrypt Data
	 * 
	 * @param data
	 * @throws IOException
	 */
	private byte[] decryptData(byte[] data, String filename) throws IOException {
		System.out.println("\n----------------DECRYPTION STARTED------------");
		byte[] descryptedData = null;

		try {
			PrivateKey privateKey = readPrivateKeyFromFile(filename);
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			descryptedData = cipher.doFinal(data);
			System.out.println("Decrypted Data: " + new String(descryptedData));

		} catch (Exception e) {
			e.printStackTrace();
		}

		System.out.println("----------------DECRYPTION COMPLETED------------");
		return descryptedData;
	}

	/**
	 * Encrypt Data
	 * 
	 * @param data
	 * @throws IOException
	 */
	private String decryptDataWithPublicKey(byte[] data, String filename)
			throws IOException {
		System.out.println("\n----------------DECRYPTION STARTED------------");
		byte[] descryptedData = null;

		try {
			PublicKey publicKey = readPublicKeyFromFile(filename);
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, publicKey);
			descryptedData = cipher.doFinal(data);
			System.out.println("Decrypted Data: " + new String(descryptedData));

		} catch (Exception e) {
			e.printStackTrace();
		}

		System.out.println("----------------DECRYPTION COMPLETED------------");
		return new String(descryptedData);
	}

	/**
	 * read Public Key From File
	 * 
	 * @param fileName
	 * @return PublicKey
	 * @throws IOException
	 */
	public PublicKey readPublicKeyFromFile(String fileName) throws IOException {
		FileInputStream fis = null;
		ObjectInputStream ois = null;
		try {
			fis = new FileInputStream(new File(fileName));
			ois = new ObjectInputStream(fis);

			BigInteger modulus = (BigInteger) ois.readObject();
			BigInteger exponent = (BigInteger) ois.readObject();

			// Get Public Key
			RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(modulus,
					exponent);
			KeyFactory fact = KeyFactory.getInstance("RSA");
			PublicKey publicKey = fact.generatePublic(rsaPublicKeySpec);

			return publicKey;

		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			if (ois != null) {
				ois.close();
				if (fis != null) {
					fis.close();
				}
			}
		}
		return null;
	}

	/**
	 * read Public Key From File
	 * 
	 * @param fileName
	 * @return
	 * @throws IOException
	 */
	public PrivateKey readPrivateKeyFromFile(String fileName)
			throws IOException {
		FileInputStream fis = null;
		ObjectInputStream ois = null;
		try {
			fis = new FileInputStream(new File(fileName));
			ois = new ObjectInputStream(fis);

			BigInteger modulus = (BigInteger) ois.readObject();
			BigInteger exponent = (BigInteger) ois.readObject();

			// Get Private Key
			RSAPrivateKeySpec rsaPrivateKeySpec = new RSAPrivateKeySpec(
					modulus, exponent);
			KeyFactory fact = KeyFactory.getInstance("RSA");
			PrivateKey privateKey = fact.generatePrivate(rsaPrivateKeySpec);

			return privateKey;

		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			if (ois != null) {
				ois.close();
				if (fis != null) {
					fis.close();
				}
			}
		}
		return null;
	}

	/**
	 * Save Files
	 * 
	 * @param fileName
	 * @param mod
	 * @param exp
	 * @throws IOException
	 */
	private void saveKeys(String fileName, BigInteger mod, BigInteger exp)
			throws IOException {
		FileOutputStream fos = null;
		ObjectOutputStream oos = null;

		try {
			System.out.println("Generating " + fileName + "...");
			fos = new FileOutputStream(fileName);
			oos = new ObjectOutputStream(new BufferedOutputStream(fos));

			oos.writeObject(mod);
			oos.writeObject(exp);

			System.out.println(fileName + " generated successfully");
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			if (oos != null) {
				oos.close();

				if (fos != null) {
					fos.close();
				}
			}
		}
	}

	private String decryptBySymmetricKey(byte[] encryptionBytes, Key pkey,
			Cipher c) throws InvalidKeyException, BadPaddingException,
			IllegalBlockSizeException {

		c.init(Cipher.DECRYPT_MODE, pkey);

		byte[] decrypt = c.doFinal(encryptionBytes);

		String decrypted = new String(decrypt);

		return decrypted;
	}

}
