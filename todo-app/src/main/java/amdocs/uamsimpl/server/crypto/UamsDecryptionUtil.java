package amdocs.uamsimpl.server.crypto;

import java.lang.reflect.Method;

public class UamsDecryptionUtil {
	
	private static boolean CUST_ENCRYPTION_ENABLED = false;
//	private static String encryClassName,encryMethodName, decryClassName,decryMethodName;
	private static Method encryMethodCheck = null, decryMethodCheck = null;
	private static Object encryObjCheck = null, decryObjCheck = null;
	// private static Map<String,String> hashMap=new HashMap<String,String>();

	public static boolean isCUST_ENCRYPTION_ENABLED() {
		return CUST_ENCRYPTION_ENABLED;
	}

	public static void setCUST_ENCRYPTION_ENABLED(boolean cUST_ENCRYPTION_ENABLED) {
		CUST_ENCRYPTION_ENABLED = cUST_ENCRYPTION_ENABLED;
	}

	static {
	  String cust_encrypt_chck = System.getenv("CUST_ENCRYPT_CHCK");
	  String custom_decryption = System.getenv("CUSTOM_DECRYPTION");
	  
	  	System.out.println("ASM::CUST PF inside if in Static block");
	  
	  
	  ClassLoader currentThreadClassLoader = Thread.currentThread().getContextClassLoader();
		if ((cust_encrypt_chck != null
				&& (cust_encrypt_chck.length() != 0 || !cust_encrypt_chck.isEmpty()))) {
			
			setCUST_ENCRYPTION_ENABLED(true);
			String encryClassName, encryMethodName;

			String[] strEncryCheck = cust_encrypt_chck.split(";");
			encryClassName = strEncryCheck[0];
			encryMethodName = strEncryCheck[1];
		//	System.out.println("ASM::CUST PF isCustEncrypted className=" + encryClassName + " methodName=" + encryMethodName);
			
			try {
			Class encryptCustomizedCallbackClass = currentThreadClassLoader.loadClass(encryClassName);
			encryObjCheck = encryptCustomizedCallbackClass.newInstance();
			encryMethodCheck = encryptCustomizedCallbackClass.getMethod(encryMethodName,
					new Class[] { String.class });
			}catch(Exception e) {
				System.out.println("ASM::CUST PF isCustEncrypted className=" + encryClassName + " methodName=" + encryMethodName);
				System.out.println("Invalid Value set for Property CUST_ENCRYPT_CHCK, Exception while classloading " + e.getMessage());
				System.err.println(e.getMessage());
				e.printStackTrace();
			}
			
		}
		if( (custom_decryption != null && (custom_decryption.length() != 0 	|| !custom_decryption.isEmpty()))) {
			String decryClassName, decryMethodName;

			String[] strDecryCheck = custom_decryption.split(";");
			decryClassName = strDecryCheck[0];
			decryMethodName = strDecryCheck[1];

	//		System.out.println("ASM::CUST PF custDecrypt className=" + decryClassName + " methodName=" + decryMethodName);

			try {
				
				Class decryptCustomizedCallbackClass = currentThreadClassLoader.loadClass(decryClassName);

				decryObjCheck = decryptCustomizedCallbackClass.newInstance();
				decryMethodCheck = decryptCustomizedCallbackClass.getMethod(decryMethodName,
						new Class[] { String.class });

			} catch (Exception e) {
				System.out.println("ASM::CUST PF custDecrypt className=" + decryClassName + " methodName=" + decryMethodName);
				System.out.println("Invalid Value set for Property CUSTOM_DECRYPTION, Exception while classloading " + e.getMessage());
				System.err.println(e.getMessage());
				e.printStackTrace();
			}

		//	System.out.println("ASM::CUST PF end of  If in Static block");
		}
	}

	public boolean isCustEncrypted(String value) {
		boolean isCustomEncryptedRetVal = false;
		try {

			isCustomEncryptedRetVal = ((Boolean) encryMethodCheck.invoke(encryObjCheck, new Object[] { value }))
					.booleanValue();
	//		System.out.println("ASM::CUST PF custDecrypt isCustomEncryptedRetVal=" + isCustomEncryptedRetVal);
		} catch (Exception e) {
			System.out.println("Exception while calling Custom isEncrypted method");
			e.printStackTrace();
		}
		return isCustomEncryptedRetVal;
	}

	public String custDecrypt(String value) {
		String decryptedValue = "";
		try {

			decryptedValue = (String) decryMethodCheck.invoke(decryObjCheck, new Object[] { value });
	//		System.out.println("ASM::CUST PF custDecrypt decryptedValue=" + decryptedValue);
		} catch (Exception e) {
			System.out.println("Exception custDecrypt while calling Custom isEncrypted method");
			e.printStackTrace();
		}
		return decryptedValue;
	}
}
