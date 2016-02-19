import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import org.apache.commons.codec.binary.Base64;


public class alice {

	public static void main(String[] args) throws FileNotFoundException {
		Socket AliceSocket = null;
		DataInputStream in = null;
		DataOutputStream out = null;
		
		String BobPublicKey = "";
		String BobSignature = "";
		
		alice alice = new alice();
		
		//Ask user for message
		System.out.print("Please type the message you would like to send to Bob:");
		Scanner scan = new Scanner(System.in);
		String message = scan.nextLine();
		
		//Save this message into the file
		PrintWriter writer = new PrintWriter("message.txt");
		writer.println(message);
		writer.close();
		
		
		try{
			AliceSocket = new Socket("", Integer.parseInt(args[0]));
			in = new DataInputStream(AliceSocket.getInputStream());
			out = new DataOutputStream(AliceSocket.getOutputStream());
		}
		catch(IOException e)
		{
			e.printStackTrace();
		}
		
		if(AliceSocket !=null && in !=null && out !=null)
		{
			try{
				//out.write("Hello".getBytes());
//				int len = 1024;
//				out.writeInt(1024);
//				if(len > 0)
//				{
//					out.write("Hello".getBytes());
//				}
				
//				byte[] message = new byte[1024];
//				int length = 0;
//				while((length = in.read(message))!=-1)
//				{
//					out.write(message, 0, length);
//				}
//				System.out.println(out.toString());
//				

				 	out.writeBytes("HELLO\n");    

	                String responseLine;
	                while ((responseLine = in.readLine()) != null) {
	                    System.out.println("Response From Server: " + responseLine);
	                    if (responseLine.equals("OK")) {
	                      BobPublicKey = in.readLine();
	                      BobSignature = in.readLine();
	              		  byte[] BobPublicKeyBytes = Base64.decodeBase64(BobPublicKey);
	              		  byte[] BobSignatureBytes = Base64.decodeBase64(BobSignature);
	              		  
	              		  PublicKey CPublicKey = alice.readPublicKeyFromFile("CPublic.Key");
	              		  
	              		  Signature sig = Signature.getInstance("SHA1withRSA");
	              		  sig.initVerify(CPublicKey);
	              		  sig.update(BobPublicKeyBytes);
	              		  boolean verifies = sig.verify(BobSignatureBytes);
	                      
	              		  System.out.println("The verification is " + verifies);
	              		  if(verifies)
	              		  {
	              			  System.out.println("This Public Key is truely from Bob.");
	              			  
	              			//Message digest
	              			MessageDigest md = MessageDigest.getInstance("SHA-1");
	              	        FileInputStream fis = new FileInputStream("message.txt");
	              	 
	              	        byte[] dataBytes = new byte[1024];
	              	 
	              	        int nread = 0; 
	              	        while ((nread = fis.read(dataBytes)) != -1) {
	              	          md.update(dataBytes, 0, nread);
	              	        };
	              	        byte[] mdbytes = md.digest();
	              	        fis.close();
	              	        
	              	        //convert the message digest to hex format
	              	        StringBuffer sb = new StringBuffer();
	              	        for (int i = 0; i < mdbytes.length; i++) {
	              	          sb.append(Integer.toString((mdbytes[i] & 0xff) + 0x100, 16).substring(1));
	              	        }
	              	        
	              	        System.out.println("Message Digest: " + sb.toString());
	              	        
	              	        //Encrypt this message digest with Alice's private key
	              	        byte[] encryptedMessageDigest = alice.encryptDataWithPrivateKey(sb.toString(), "AlicePrivate.key");
	              	        //alice.decryptDataWithPublicKey(encryptedMessageDigest, "AlicePrivate.key");
	              	        
	              	       //Generating Symmetric Key
	              	        SecretKey symKey = KeyGenerator.getInstance("DESede").generateKey();
	              	        Cipher c = Cipher.getInstance("DESede");
	              	        
	              	        //Recover Bob's Public Key
	              	        PublicKey Bob =  KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(BobPublicKeyBytes));
	              	        
	              	        //Using Bob's Public Key to encrypt the symmetric key
	              	        //String SymmetricKeyInString = Base64.encodeBase64String(symKey.getEncoded());
	              	        //System.out.println(symKey.getEncoded().toString());
	              	        Cipher c1 = Cipher.getInstance("RSA");
	              	        c1.init(Cipher.ENCRYPT_MODE, Bob);
	              	        //byte[] encryptedSymmetricKey = alice.encryptData(SymmetricKeyInString, Bob);
	              	        String encryptedSymmetricKeyInString = Base64.encodeBase64String(c1.doFinal(symKey.getEncoded()));
	              	        
	              	        //Using Symmetric key to encrypt the encrypted message digest
	              	        String encryptedMessageDigestInString = Base64.encodeBase64String(encryptedMessageDigest);
	              	        System.out.println(encryptedMessageDigestInString);
	              	        byte[] encryptionOfencryptedMessageDigest = alice.encryptBySymmetricKey(encryptedMessageDigestInString,symKey,c);
	              	        String encryptionOfencryptedMessageDigestInString = Base64.encodeBase64String(encryptionOfencryptedMessageDigest);
	              	        
	              	        //Using Symmetric key to encrypt the original message
	              	        byte[] encryptionOfOriginalMessage = alice.encryptBySymmetricKey(message,symKey,c);
	              	        String encryptionOfOriginalMessageInString = Base64.encodeBase64String(encryptionOfOriginalMessage);
	              	        
	              	        out.writeBytes(encryptionOfOriginalMessageInString+"\n");
	              	        out.writeBytes(encryptionOfencryptedMessageDigestInString+"\n");
	              	        out.writeBytes(encryptedSymmetricKeyInString+"\n");    
	              		  }
	              		  else
	              		  {
	              			  System.out.println("This Public Key is not Bob.");
	              			  System.out.println("Close the connection.");
	              			  out.close();
	              			  in.close();
	              			  AliceSocket.close(); 
	              		  }
	                    }

	                }

	                out.close();
	                in.close();
	                AliceSocket.close(); 
				
			}
			catch(IOException e)
			{
				e.printStackTrace();
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (InvalidKeyException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (SignatureException e) {
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
			} catch (InvalidKeySpecException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	}
	
	/**
	 * Encrypt Data
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
	 * @param data
	 * @throws IOException
	 */
	private byte[] encryptData(String data, PublicKey p) throws IOException {
		System.out.println("\n----------------ENCRYPTION STARTED------------");
		
		System.out.println("Data Before Encryption :" + data);
		byte[] dataToEncrypt = data.getBytes();
		byte[] encryptedData = null;
		try {
			PublicKey pubKey = p;
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
	 * @param data
	 * @throws IOException
	 */
	private byte[] encryptDataWithPrivateKey(String data, String filename) throws IOException {
		System.out.println("\n----------------ENCRYPTION STARTED------------");
		
		System.out.println("Data Before Encryption :" + data);
		byte[] dataToEncrypt = data.getBytes();
		byte[] encryptedData = null;
		try {
			PrivateKey privatekey = readPrivateKeyFromFile(filename);
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, privatekey);
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
	 * @param data
	 * @throws IOException
	 */
	private void decryptData(byte[] data, String filename) throws IOException {
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
	}
	
	/**
	 * Encrypt Data
	 * @param data
	 * @throws IOException
	 */
	private void decryptDataWithPublicKey(byte[] data, String filename) throws IOException {
		System.out.println("\n----------------DECRYPTION STARTED------------");
		byte[] descryptedData = null;
		
		try {
			PublicKey publickey = readPublicKeyFromFile(filename);
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, publickey);
			descryptedData = cipher.doFinal(data);
			System.out.println("Decrypted Data: " + new String(descryptedData));
			
		} catch (Exception e) {
			e.printStackTrace();
		}	
		
		System.out.println("----------------DECRYPTION COMPLETED------------");		
	}
	
	/**
	 * read Public Key From File
	 * @param fileName
	 * @return PublicKey
	 * @throws IOException
	 */
	public PublicKey readPublicKeyFromFile(String fileName) throws IOException{
		FileInputStream fis = null;
		ObjectInputStream ois = null;
		try {
			fis = new FileInputStream(new File(fileName));
			ois = new ObjectInputStream(fis);
			
			BigInteger modulus = (BigInteger) ois.readObject();
		    BigInteger exponent = (BigInteger) ois.readObject();
			
		    //Get Public Key
		    RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(modulus, exponent);
		    KeyFactory fact = KeyFactory.getInstance("RSA");
		    PublicKey publicKey = fact.generatePublic(rsaPublicKeySpec);
		    		    
		    return publicKey;
		    
		} catch (Exception e) {
			e.printStackTrace();
		}
		finally{
			if(ois != null){
				ois.close();
				if(fis != null){
					fis.close();
				}
			}
		}
		return null;
	}
	
	/**
	 * read Public Key From File
	 * @param fileName
	 * @return
	 * @throws IOException
	 */
	public PrivateKey readPrivateKeyFromFile(String fileName) throws IOException{
		FileInputStream fis = null;
		ObjectInputStream ois = null;
		try {
			fis = new FileInputStream(new File(fileName));
			ois = new ObjectInputStream(fis);
			
			BigInteger modulus = (BigInteger) ois.readObject();
		    BigInteger exponent = (BigInteger) ois.readObject();
			
		    //Get Private Key
		    RSAPrivateKeySpec rsaPrivateKeySpec = new RSAPrivateKeySpec(modulus, exponent);
		    KeyFactory fact = KeyFactory.getInstance("RSA");
		    PrivateKey privateKey = fact.generatePrivate(rsaPrivateKeySpec);
		    		    
		    return privateKey;
		    
		} catch (Exception e) {
			e.printStackTrace();
		}
		finally{
			if(ois != null){
				ois.close();
				if(fis != null){
					fis.close();
				}
			}
		}
		return null;
	}
	
    private byte[] encryptBySymmetricKey(String input,Key pkey,Cipher c) throws InvalidKeyException, BadPaddingException,IllegalBlockSizeException {

		  c.init(Cipher.ENCRYPT_MODE, pkey);
		
		  byte[] inputBytes = input.getBytes();
		
		  return c.doFinal(inputBytes);
    }

    private String decryptBySymmetricKey(byte[] encryptionBytes,Key pkey,Cipher c) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

		  c.init(Cipher.DECRYPT_MODE, pkey);
		
		  byte[] decrypt = c.doFinal(encryptionBytes);
		
		  String decrypted = new String(decrypt);
		
		  return decrypted;
    }
	

}
