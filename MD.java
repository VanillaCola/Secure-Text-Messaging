import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;


public class MD {

	public static void main(String[] agrs) throws NoSuchAlgorithmException, IOException
	{
		PrintWriter out = new PrintWriter("test.txt");
		out.println("This is a test");
		out.close();
		
		MessageDigest md = MessageDigest.getInstance("SHA-1");
        FileInputStream fis = new FileInputStream("test.txt");
 
        byte[] dataBytes = new byte[1024];
 
        int nread = 0; 
        while ((nread = fis.read(dataBytes)) != -1) {
          md.update(dataBytes, 0, nread);
        };
        byte[] mdbytes = md.digest();
        fis.close();
 
        //convert the byte to hex format method 1
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < mdbytes.length; i++) {
          sb.append(Integer.toString((mdbytes[i] & 0xff) + 0x100, 16).substring(1));
        }
 
        System.out.println("Hex format : " + sb.toString());
 
       //convert the byte to hex format method 2
        StringBuffer hexString = new StringBuffer();
    	for (int i=0;i<mdbytes.length;i++) {
    	  hexString.append(Integer.toHexString(0xFF & mdbytes[i]));
    	}
 
    	System.out.println("Hex format : " + hexString.toString());
	}
}
