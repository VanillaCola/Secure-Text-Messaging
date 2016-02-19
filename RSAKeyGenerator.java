import java.io.BufferedOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;


public class RSAKeyGenerator {
	
	// TODO Auto-generated method stub
	private static final String Certificate_PUBLIC_KEY_FILE = "CPublic.key";
	private static final String Certificate_PRIVATE_KEY_FILE = "CPrivate.key";
	private static final String Alice_PUBLIC_KEY_FILE = "AlicePublic.key";
	private static final String Alice_PRIVATE_KEY_FILE = "AlicePrivate.key";
	

	public static void main(String[] args){
		try {
			System.out.println("-------GENRATE PUBLIC and PRIVATE KEY-------------");
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(1024); //1024 used for normal securities
			KeyPair keyPair = keyPairGenerator.generateKeyPair();
			PublicKey publicKey = keyPair.getPublic();
			PrivateKey privateKey = keyPair.getPrivate();
			System.out.println("Alice Public Key - " + publicKey);
			System.out.println("Alice Private Key - " + privateKey);
			
			System.out.println("Get Certificate Key pairs");
			KeyPair cKeypair = keyPairGenerator.generateKeyPair();
			PublicKey cpublicKey = cKeypair.getPublic();
			PrivateKey cprivateKey = cKeypair.getPrivate();
			System.out.println("Certificate Public Key - " + cpublicKey);
			System.out.println("Certificate Private Key - " + cprivateKey);
			

			//Pullingout parameters which makes up Key
			System.out.println("\n------- PULLING OUT PARAMETERS WHICH MAKES KEYPAIR----------\n");
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			RSAPublicKeySpec rsaPubKeySpec = keyFactory.getKeySpec(publicKey, RSAPublicKeySpec.class);
			RSAPrivateKeySpec rsaPrivKeySpec = keyFactory.getKeySpec(privateKey, RSAPrivateKeySpec.class);
			RSAPublicKeySpec rsaCPubKeySpec = keyFactory.getKeySpec(cpublicKey, RSAPublicKeySpec.class);
			RSAPrivateKeySpec rsaCPrivKeySpec = keyFactory.getKeySpec(cprivateKey, RSAPrivateKeySpec.class);
			System.out.println("PubKey Modulus : " + rsaPubKeySpec.getModulus());
			System.out.println("PubKey Exponent : " + rsaPubKeySpec.getPublicExponent());
			System.out.println("PrivKey Modulus : " + rsaPrivKeySpec.getModulus());
			System.out.println("PrivKey Exponent : " + rsaPrivKeySpec.getPrivateExponent());
			
			System.out.println("PubKey Modulus : " + rsaCPubKeySpec.getModulus());
			System.out.println("PubKey Exponent : " + rsaCPubKeySpec.getPublicExponent());
			System.out.println("PrivKey Modulus : " + rsaCPrivKeySpec.getModulus());
			System.out.println("PrivKey Exponent : " + rsaCPrivKeySpec.getPrivateExponent());
			
			
			//Share public key with other so they can encrypt data and decrypt thoses using private key(Don't share with Other)
			System.out.println("\n--------SAVING PUBLIC KEY AND PRIVATE KEY TO FILES-------\n");
			RSAKeyGenerator rsaObj = new RSAKeyGenerator();

				rsaObj.saveKeys(Certificate_PUBLIC_KEY_FILE, rsaCPubKeySpec.getModulus(), rsaCPubKeySpec.getPublicExponent());
				rsaObj.saveKeys(Certificate_PRIVATE_KEY_FILE, rsaCPrivKeySpec.getModulus(), rsaCPrivKeySpec.getPrivateExponent());
				rsaObj.saveKeys(Alice_PUBLIC_KEY_FILE, rsaPubKeySpec.getModulus(), rsaPubKeySpec.getPublicExponent());
				rsaObj.saveKeys(Alice_PRIVATE_KEY_FILE, rsaPrivKeySpec.getModulus(), rsaPrivKeySpec.getPrivateExponent());


			
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}catch (IOException e)
		{
			e.printStackTrace();
		}
		
		
	}
	
	/**
	 * Save Files
	 * @param fileName
	 * @param mod
	 * @param exp
	 * @throws IOException
	 */
	private void saveKeys(String fileName,BigInteger mod,BigInteger exp) throws IOException{
		FileOutputStream fos = null;
		ObjectOutputStream oos = null;
		
		try {
			System.out.println("Generating "+fileName + "...");
			fos = new FileOutputStream(fileName);
			oos = new ObjectOutputStream(new BufferedOutputStream(fos));
			
			oos.writeObject(mod);
			oos.writeObject(exp);			
			
			System.out.println(fileName + " generated successfully");
		} catch (Exception e) {
			e.printStackTrace();
		}
		finally{
			if(oos != null){
				oos.close();
				
				if(fos != null){
					fos.close();
				}
			}
		}		
	}

}
