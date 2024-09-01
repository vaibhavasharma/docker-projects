package amdocs.uamsimpl.server.crypto.stub;

import amdocs.uams.module.UamsAbstractModule;
import amdocs.uamsimpl.server.crypto.UamsDecryptionUtil;
import amdocs.uamsimpl.shared.utils.debug.DebugLog;
import amdocs.uams.crypto.UamsEncryptionService;
import amdocs.uams.log.UamsLog;
import amdocs.uams.UamsService;
import amdocs.uams.UamsOperationException;
import amdocs.uams.UamsSecurityException;

/**
 * UAMS
 *
 * User: pavelp
 * Date: Feb 27, 2005
 */
public class UamsEncryptionStubModule extends UamsAbstractModule {

    /*static {
    	DebugLog.log(UamsLog.S_UAMS_DEBUG, UamsLog.F_UAMS_ENCRYPTION_SERVICE, "Cust encryption UamsEncryptionStubModule");
    //	System.out.println("ASM::CUST PF for cust encryption UamsEncryptionStubModule");
    }*/
    
    protected UamsService createService() throws UamsOperationException {
        return new UamsEncryptionStub();
    }

    private class UamsEncryptionStub implements UamsEncryptionService {

        public String encryptMsg(Object session, String resourceName, byte[] message) throws UamsSecurityException, UamsOperationException {
            try {
                Thread.currentThread().sleep(2000);
            } catch (InterruptedException e) {
            }
            String res = new String(message);
            return "_"+res;
        }

        public byte[] decryptMsg(Object session, String resourceName, String message) throws UamsSecurityException, UamsOperationException {
        //	System.out.println("ASM::CUST PF decryptMsg UamsEncryptionStubModule$UamsEncryptionStub");
        	
        	try {
                Thread.currentThread().sleep(2000);
            } catch (InterruptedException e) {
            }
            UamsDecryptionUtil decryptionUtil= new UamsDecryptionUtil();
			boolean useCustEncryption = UamsDecryptionUtil.isCUST_ENCRYPTION_ENABLED();
			 if (useCustEncryption == true){
	            	return	decryptionUtil.custDecrypt(message).getBytes();
				}
			else {
				if (!(message.startsWith("_"))){
					throw new UamsOperationException("This is not a valid encrypted message");
				}
				String orig = message.substring(1,message.length());
				return orig.getBytes();
				}
        }

        public boolean isEncrypted(Object session, String resourceName, String message) throws UamsSecurityException, UamsOperationException {
        	//System.out.println("ASM::CUST PF isEncrypted UamsEncryptionStubModule$UamsEncryptionStub");
        	UamsDecryptionUtil decryptionUtil= new UamsDecryptionUtil();
			boolean useCustEncryption = UamsDecryptionUtil.isCUST_ENCRYPTION_ENABLED();
			if (useCustEncryption){
				return	(decryptionUtil.isCustEncrypted(message));
				
			}
			else {
				return message.startsWith("_");
            }
        }
    }

/*	public static void main(String[] args) throws Exception {
		UamsEncryptionStubModule module = new UamsEncryptionStubModule();
		UamsEncryptionService crypto = (UamsEncryptionService) module.createService();
		String message = "message";
		String encrypted = crypto.encryptMsg(null, null, message.getBytes());
		System.out.println("encrypted = " + encrypted);
		byte[] decrypted = crypto.decryptMsg(null, null, encrypted);
		System.out.println("decrypted = " + new String(decrypted));
		crypto.decryptMsg(null, null, message);
	}*/

}
