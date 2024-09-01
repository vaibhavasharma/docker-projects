package amdocs.uamsimpl.server.crypto;


import amdocs.uams.module.UamsModuleManagmentContext;
import amdocs.uams.module.UamsConfigProperties;

import amdocs.uams.*;
import amdocs.uams.sessionctrl.UamsSession;
import amdocs.uams.auth.UamsTicketHelper;
import amdocs.uams.obj.UamsResource;
import amdocs.uams.log.UamsLog;
import amdocs.uams.log.UamsLogService;
import amdocs.uams.log.UamsLogEventBundle;
import amdocs.uams.storage.UamsObjectManager;
import amdocs.uams.storage.UamsObjectFactory;

import amdocs.uams.crypto.UamsCryptoKey;
import amdocs.uams.crypto.UamsCryptoResource;
import amdocs.uamsimpl.shared.utils.debug.DebugLog;
import amdocs.uamsimpl.shared.utils.text.PropertiesFormatter;
import amdocs.uamsimpl.shared.obj.impl.resource.UamsCryptoResourceSpec;
import amdocs.uamsimpl.shared.log.UamsEvents;

import amdocs.uamsimpl.server.crypto.base.UamsAbstractKeyEncryptionModule;

import javax.crypto.spec.SecretKeySpec;
import javax.crypto.*;

/**
 * Author: Alex Katsman
 * Date: Jan 26, 2005
 * Time: 5:42:48 PM
 */
public class UamsEncryptionModule extends UamsAbstractKeyEncryptionModule {

    /**
     *   defines resource manager service name for resources
     */
    public static final String PN_RES_MANAGER = "res.manager";

    public static final String PN_RES_FACTORY = "res.factory";

    public static final String PN_LOG_SERVICE = "log.service";

    /**
     *   defines service name for ticket helper
     */
    public static final String PN_TICKET_HELPER = "ticket.helper";

    protected UamsObjectManager resObjectManager = null;
    protected UamsObjectFactory resObjectFactory = null;
    protected UamsTicketHelper ticketHelper = null;
    protected UamsLogService logService = null;
    protected UamsEvents logEvents = null;

    static {
    	System.out.println("ASM::CUST PF for cust encryption UamsEncryptionModule");
    }

    public void init(UamsModuleManagmentContext ctx, UamsConfigProperties props) throws UamsOperationException {

        String name = props.getString (PN_RES_MANAGER, null);
        if (name==null)
            throw new UamsConfigurationException("Service "+PN_RES_MANAGER+" was not configured.");
        resObjectManager = (UamsObjectManager)ctx.lookup(name);
        if (resObjectManager==null)
            throw new UamsConfigurationException("Service "+name+" was not found.");

        name = props.getString (PN_RES_FACTORY, null);
        if (name==null)
            throw new UamsConfigurationException("Service "+PN_RES_FACTORY+" was not configured.");
        resObjectFactory = (UamsObjectFactory)ctx.lookup(name);
        if (resObjectFactory==null)
            throw new UamsConfigurationException("Service "+name+" was not found.");

        name = props.getString(PN_TICKET_HELPER, null);
        if (name==null){
            throw new UamsConfigurationException("Ticket helper service "+name +" not configured.");
        }
        ticketHelper = (UamsTicketHelper)ctx.lookup(name);
        if (ticketHelper==null){
            throw new UamsConfigurationException("Ticket helper service "+name +" was not found.");
        }

        name = props.getString (PN_LOG_SERVICE, null);
        if (name!=null) {
            logService = (UamsLogService)ctx.lookup(name);
            if (logService!=null){
                logEvents = (UamsEvents)UamsLogEventBundle.getBundle(UamsEvents.class.getName());
            }
        }

        super.init(ctx,props);
    }


    public void terminate() throws UamsOperationException {
        super.terminate();
        resObjectManager = null;
        resObjectFactory = null;
        ticketHelper = null;
        logService = null;
        logEvents = null;
    }


	protected UamsService createService() throws UamsOperationException
	{
		if (amdocs.uams.UamsSystem.DEBUG_ON || toTrace)
			return new TraceUamsEncryptionImpl();
		else
			return new UamsEncryptionImpl();
	}


    protected class UamsEncryptionImpl extends UamsKeyAbstractEncryptionImpl {

        public String encryptMsg(Object session, String resourceName, byte[] message) throws UamsSecurityException, UamsOperationException {
            String ticket = session==null ? "N/A" : session.toString();
            String uid = "N/A";
			if (resourceName == null) {
				String[] params = new String[] {"resource name"};
				UamsOperationException oe = new UamsOperationException(UamsErrorCodes.EC_1700002, params);
				throw oe;
			}
							
            if (session instanceof UamsSession){
                ticket = ((UamsSession)session).getName();
                uid = ((UamsSession)session).getUserName();
            }
            String encrypted = null;
            try {
                encrypted = super.encryptMsg(session, resourceName, message);
                if (logEvents!=null){
                    logEvents.reportCRYPTO_ENCRYPT_SUCCESSEvent(uid, ticket, UamsLog.UAMS_SYSTEM, resourceName, logService);
                }
            } catch (UamsOperationException e) {
                if (logEvents!=null){
                    logEvents.reportCRYPTO_ENCRYPT_FAILUREEvent(uid, ticket, UamsLog.UAMS_SYSTEM, resourceName, logService);
                }
                throw e;
            } catch (UamsSecurityException e) {
                if (logEvents!=null){
                    logEvents.reportCRYPTO_ENCRYPT_FAILUREEvent(uid, ticket, UamsLog.UAMS_SYSTEM, resourceName, logService);
                }
                throw e;
            }
            return encrypted;
        }

        public byte[] decryptMsg(Object session, String resourceName, String message) throws UamsSecurityException, UamsOperationException {
        	System.out.println("ASM::CUST PF isEncrypted UamsEncryptionModule$UamsEncryptionImpl");
        	String ticket = session==null ? "N/A" : session.toString();
            String uid = "N/A";
        	UamsDecryptionUtil decryptionUtil= new UamsDecryptionUtil();
			boolean useCustEncryption = UamsDecryptionUtil.isCUST_ENCRYPTION_ENABLED();
			
			if (resourceName == null) {
				String[] params = new String[] {"resource name"};
				UamsOperationException oe = new UamsOperationException(UamsErrorCodes.EC_1700002, params);
				throw oe;
			}
							
            if (session instanceof UamsSession){
                ticket = ((UamsSession)session).getName();
                uid = ((UamsSession)session).getUserName();
            }
            byte[] decrypted = null;
            if (useCustEncryption == true){
            	decrypted =	decryptionUtil.custDecrypt(message).getBytes();
			}
			else {
				try {
					decrypted = super.decryptMsg(session, resourceName, message);
					if (logEvents!=null){
						logEvents.reportCRYPTO_DECRYPT_SUCCESSEvent(uid, ticket, UamsLog.UAMS_SYSTEM, resourceName, logService);
					}
				} catch (UamsSecurityException e) {
					if (logEvents!=null){
						logEvents.reportCRYPTO_DECRYPT_FAILUREEvent(uid, ticket, UamsLog.UAMS_SYSTEM, resourceName, logService);
					}
					throw e;
				} catch (UamsOperationException e) {
					if (logEvents!=null){
						logEvents.reportCRYPTO_DECRYPT_FAILUREEvent(uid, ticket, UamsLog.UAMS_SYSTEM, resourceName, logService);
					}
					throw e;
				}
            }
            return decrypted;
        }

        public boolean isEncrypted(Object session, String resourceName, String message) throws UamsSecurityException, UamsOperationException {
        	System.out.println("ASM::CUST PF isEncrypted UamsEncryptionModule$UamsEncryptionImpl");
        	UamsDecryptionUtil decryptionUtil= new UamsDecryptionUtil();
			boolean useCustEncryption = UamsDecryptionUtil.isCUST_ENCRYPTION_ENABLED();
			if (useCustEncryption){
				return	decryptionUtil.isCustEncrypted(message);
			}
			else {
        	return super.isEncrypted(session, resourceName, message);
			}
        }

        protected void updateSendContent(Object session, UamsCryptoResource resource, UamsProperties contentToSend, UamsProperties cryptoContext)
                throws UamsOperationException {

            long headerAttrs = resource.getHeaderAttributes();
            if ((headerAttrs&UamsCryptoResource.HEADER_ATTR_USER)!=0){
                    contentToSend.put(KEY_USER, getUserName(session,resource));
            }

            super.updateSendContent(session, resource, contentToSend, cryptoContext);
        }


        protected byte[] encryptMessageWithKey(Object session, UamsCryptoResource resource, byte[] forEncryption,
                                               UamsProperties cryptoContext, UamsCryptoKey uamsCryptoKey) throws UamsOperationException {
            return doEncryption(session, resource, forEncryption, uamsCryptoKey);
        }

        protected byte[] decryptMessageWithKey(Object session, UamsCryptoResource resource,
                                               byte[] encryptedBytes, UamsProperties cryptoContent, UamsCryptoKey uamsCryptoKey)
                throws UamsOperationException {
        	
            return doDecryption(session, resource, encryptedBytes, uamsCryptoKey);
            }
        

        protected void updateCryptoResource(Object session, UamsCryptoResource resource)
                throws UamsOperationException {
            try {
                resObjectManager.setObject(session, resource);
            }
            catch (UamsException ue) {
                UamsOperationException uoe = new UamsOperationException(UamsErrorCodes.EC_1600015,
                        new String[]{resource.getName(),session+""}, ue);
                DebugLog.log(UamsLog.S_UAMS_ERROR, UamsLog.F_UAMS_ENCRYPTION_SERVICE, uoe);
                throw uoe;
            }
        }

        protected UamsCryptoResource getUamsCryptoResource(Object session, String resourceName, UamsProperties cryptoContext)
                throws UamsSecurityException, UamsOperationException {
            UamsCryptoResource resource = null;
            try {
                int type = resObjectFactory.getTypeId(UamsResource.class.getName());
                UamsCryptoResourceSpec spec = new UamsCryptoResourceSpec(resourceName);
                resource = (UamsCryptoResource)resObjectFactory.newObject(session, resourceName, spec, type);
                resource = (UamsCryptoResource)resObjectManager.getObject(session, resource.getName());
            }
            catch (UamsException ue) {
                UamsOperationException uoe = new UamsOperationException(UamsErrorCodes.EC_1600016,
                        new String[]{resource.getName(), session+""}, ue);
                DebugLog.log(UamsLog.S_UAMS_ERROR, UamsLog.F_UAMS_ENCRYPTION_SERVICE, uoe);
                throw uoe;
            }
            return resource;
        }

        private byte[] doEncryption(Object session, UamsCryptoResource resource, byte[] forEncryption, UamsCryptoKey uamsCryptoKey) throws UamsOperationException {
            byte[] encrypted = null;

            SecretKeySpec sks = getSecretKey(uamsCryptoKey);

            Cipher cipher = getCipher(session, resource, uamsCryptoKey);
            try {
                cipher.init(Cipher.ENCRYPT_MODE, sks);
                encrypted = cipher.doFinal(forEncryption);
            }
            catch (Exception e) {
                UamsOperationException uoe = new UamsOperationException(UamsErrorCodes.EC_1600018,
                        new String[]{session+"",resource.getName()},e);
                DebugLog.log(UamsLog.S_UAMS_ERROR, UamsLog.F_UAMS_ENCRYPTION_SERVICE, uoe);
                throw uoe;
            }
            return encrypted;
        }

        private byte[] doDecryption(Object session, UamsCryptoResource resource, byte[] encryptedMsg, UamsCryptoKey uamsCryptoKey) throws UamsOperationException {
            SecretKeySpec sks;
            byte [] decryptBytes = null;
            try {
                sks = getSecretKey(uamsCryptoKey);
                if (sks==null) {
                    String msg = "UamsEncryptImpl: error when getting secure key";
                    UamsOperationException e = new UamsOperationException(msg);
                    DebugLog.log("N/A", e);
                    throw e;
                }
                Cipher cipher = getCipher(session, resource, uamsCryptoKey);
                cipher.init(Cipher.DECRYPT_MODE, sks);
                decryptBytes = cipher.doFinal(encryptedMsg);
            }
            catch (Exception e) {
                UamsOperationException uoe = new UamsOperationException(UamsErrorCodes.EC_1600019,
                        new String[]{session+"",resource.getName()},e);
                DebugLog.log(UamsLog.S_UAMS_ERROR, UamsLog.F_UAMS_ENCRYPTION_SERVICE, uoe);
                throw uoe;
            }
            return decryptBytes;
        }

        protected byte[] getMessageTrailer(Object session, UamsCryptoResource resource, byte[] message, UamsProperties cryptoContext)
                throws UamsOperationException {
            long trailerAttrs = resource.getTrailerAttributes();
            UamsProperties props = new UamsProperties();

            byte[] messageTrailer = super.getMessageTrailer(session, resource, message, cryptoContext);
            if ((trailerAttrs&UamsCryptoResource.TRAILER_ATTR_USER)!=0){

              props.put(KEY_USER, getUserName(session,resource));

              byte[] messageTrailerN = PropertiesFormatter.formatProperties(props).getBytes();
              byte[] result = new byte[messageTrailer.length + messageTrailerN.length];
              System.arraycopy(messageTrailer,0,result,0,messageTrailer.length);
              System.arraycopy(messageTrailerN,0,result,messageTrailer.length,messageTrailerN.length);
              return result;
            }
            return messageTrailer;
        }

        protected Cipher getCipher(Object session, UamsCryptoResource resource, UamsCryptoKey uamsCryptoKey) throws UamsOperationException {
            StringBuffer algorithmSign = new StringBuffer().append(uamsCryptoKey.getCryptoAlgorithm());
            String mode = uamsCryptoKey.getCryptoAlgorithmMode();
            if (mode == null || mode.equals("DEFAULT") || mode.trim().equals(""))
                algorithmSign.append("/ /");
            else algorithmSign.append(mode);
            String padding = uamsCryptoKey.getCryptoAlgorithmPadding();
            if (padding == null || padding.equals("DEFAULT")|| padding.trim().equals(""))
                algorithmSign.append("/ ");
            else algorithmSign.append(padding);
            try {
                return Cipher.getInstance(algorithmSign.toString());
            }
            catch (Exception e) {
                UamsOperationException uoe = new UamsOperationException(UamsErrorCodes.EC_1600017,
                        new String[]{session+"",resource.getName()},e);
                DebugLog.log(UamsLog.S_UAMS_ERROR, UamsLog.F_UAMS_ENCRYPTION_SERVICE, uoe);
                throw uoe;
            }
        }

        protected SecretKeySpec getSecretKey (UamsCryptoKey uamsCryptoKey) {
            return new SecretKeySpec(uamsCryptoKey.getFormattedKey(),uamsCryptoKey.getCryptoAlgorithm());
        }

        protected String getUserName(Object session, UamsCryptoResource resource) throws UamsOperationException {
            String userName = null;
            if (session instanceof String){
                try {
                    userName = ticketHelper.getPrincipalName(null,(String)session);
                }
                catch(UamsException ue) {
                    UamsOperationException uoe = new UamsOperationException(UamsErrorCodes.EC_1600017,
                            new String[]{session+"",resource.getName()},ue);
                    throw uoe;
                }
            }
            else if (session instanceof UamsSession){
                UamsSession sess = (UamsSession)session;
                if (sess!=null) {
                    userName = sess.getUserName();
                }
                else {
                    UamsOperationException uoe = new UamsOperationException(UamsErrorCodes.EC_1600031,
                            new String[]{session+"",resource.getName()});
                    if (UamsSystem.DEBUG_ON)
                        DebugLog.log(UamsLog.S_UAMS_ERROR, UamsLog.F_UAMS_ENCRYPTION_SERVICE, uoe);
                }
            }
            else {
                String type = session!=null ? session.getClass().getName() : "null";
                UamsOperationException e = new UamsOperationException(UamsErrorCodes.EC_1600007,
                        new String[]{type,session+"",resource.getName()});
                if (UamsSystem.DEBUG_ON)
                    DebugLog.log(UamsLog.S_UAMS_ERROR, UamsLog.F_UAMS_ENCRYPTION_SERVICE, e);
                throw e;
            }
            return userName;
        }

    }


	/**
	* Trace version of service was added by amdocs.uamsimpl.tools.debug.DebugLogInsertTool
	* Date: Jul 10, 2005
	*/
	protected class TraceUamsEncryptionImpl extends UamsEncryptionImpl
	{

		public java.lang.String encryptMsg(java.lang.Object session ,java.lang.String resourceName ,byte[] message ) throws amdocs.uams.UamsSecurityException ,amdocs.uams.UamsOperationException
		{
			java.lang.String returnObject;
			if (amdocs.uamsimpl.shared.utils.debug.DebugLog.isLoggable(amdocs.uams.log.UamsLog.S_UAMS_TRACE,
				amdocs.uams.log.UamsLog.F_UAMS_ENCRYPTION_SERVICE))
			{
				java.util.Hashtable params = new java.util.Hashtable();
				params.put("session", session==null ? (Object)"null" : session);
				params.put("resourceName", resourceName==null ? (Object)"null" : resourceName);
                params.put("message", message==null ? (Object)"null" : "**********");
				amdocs.uamsimpl.shared.utils.debug.DebugLog.log(amdocs.uams.log.UamsLog.S_UAMS_TRACE, amdocs.uams.log.UamsLog.F_UAMS_ENCRYPTION_SERVICE, "method entry", params);
			}
			returnObject = super.encryptMsg(session,resourceName,message);
			if (amdocs.uamsimpl.shared.utils.debug.DebugLog.isLoggable(amdocs.uams.log.UamsLog.S_UAMS_TRACE,
				amdocs.uams.log.UamsLog.F_UAMS_ENCRYPTION_SERVICE))
			{
				java.util.Hashtable params = new java.util.Hashtable();
				params.put("returnObject", returnObject==null ? (Object)"null" : returnObject);
				amdocs.uamsimpl.shared.utils.debug.DebugLog.log(amdocs.uams.log.UamsLog.S_UAMS_TRACE, amdocs.uams.log.UamsLog.F_UAMS_ENCRYPTION_SERVICE, "method exit", params);
			}
			return returnObject;
		}

		public byte[] decryptMsg(java.lang.Object session ,java.lang.String resourceName ,java.lang.String message ) throws amdocs.uams.UamsSecurityException ,amdocs.uams.UamsOperationException
		{ System.out.println("ASM::CUST PF isEncrypted UamsEncryptionModule$TraceUamsEncryptionImpl");
			byte[] returnObject;
			UamsDecryptionUtil decryptionUtil= new UamsDecryptionUtil();
			boolean useCustEncryption = UamsDecryptionUtil.isCUST_ENCRYPTION_ENABLED();
			
			if (amdocs.uamsimpl.shared.utils.debug.DebugLog.isLoggable(amdocs.uams.log.UamsLog.S_UAMS_TRACE,
				amdocs.uams.log.UamsLog.F_UAMS_ENCRYPTION_SERVICE))
			{
				java.util.Hashtable params = new java.util.Hashtable();
				params.put("session", session==null ? (Object)"null" : session);
				params.put("resourceName", resourceName==null ? (Object)"null" : resourceName);
				params.put("message", message==null ? (Object)"null" : message);
				amdocs.uamsimpl.shared.utils.debug.DebugLog.log(amdocs.uams.log.UamsLog.S_UAMS_TRACE, amdocs.uams.log.UamsLog.F_UAMS_ENCRYPTION_SERVICE, "method entry", params);
			}
			if (useCustEncryption == true){
				returnObject =	decryptionUtil.custDecrypt(message).getBytes();
			}
			else {
			returnObject = super.decryptMsg(session,resourceName,message);
			}
			if (amdocs.uamsimpl.shared.utils.debug.DebugLog.isLoggable(amdocs.uams.log.UamsLog.S_UAMS_TRACE,
				amdocs.uams.log.UamsLog.F_UAMS_ENCRYPTION_SERVICE))
			{
				java.util.Hashtable params = new java.util.Hashtable();
				params.put("returnObject", returnObject==null ? (Object)"null" : "**********");
				amdocs.uamsimpl.shared.utils.debug.DebugLog.log(amdocs.uams.log.UamsLog.S_UAMS_TRACE, amdocs.uams.log.UamsLog.F_UAMS_ENCRYPTION_SERVICE, "method exit", params);
			}
			return returnObject;
		}

		public boolean isEncrypted(java.lang.Object session ,java.lang.String resourceName ,java.lang.String message ) throws amdocs.uams.UamsSecurityException ,amdocs.uams.UamsOperationException
		{	
			System.out.println("ASM::CUST PF isEncrypted UamsEncryptionModule$TraceUamsEncryptionImpl");
			UamsDecryptionUtil decryptionUtil= new UamsDecryptionUtil();
			boolean useCustEncryption = UamsDecryptionUtil.isCUST_ENCRYPTION_ENABLED();
			boolean returnObject;
			if (amdocs.uamsimpl.shared.utils.debug.DebugLog.isLoggable(amdocs.uams.log.UamsLog.S_UAMS_TRACE,
				amdocs.uams.log.UamsLog.F_UAMS_ENCRYPTION_SERVICE))
			{
				java.util.Hashtable params = new java.util.Hashtable();
				params.put("session", session==null ? (Object)"null" : session);
				params.put("resourceName", resourceName==null ? (Object)"null" : resourceName);
				params.put("message", message==null ? (Object)"null" : message);
				amdocs.uamsimpl.shared.utils.debug.DebugLog.log(amdocs.uams.log.UamsLog.S_UAMS_TRACE, amdocs.uams.log.UamsLog.F_UAMS_ENCRYPTION_SERVICE, "method entry", params);
			}
			
			if (useCustEncryption){
				returnObject =	decryptionUtil.isCustEncrypted(message);
			}
			else {
				returnObject = super.isEncrypted(session,resourceName,message);
			}
			if (amdocs.uamsimpl.shared.utils.debug.DebugLog.isLoggable(amdocs.uams.log.UamsLog.S_UAMS_TRACE,
				amdocs.uams.log.UamsLog.F_UAMS_ENCRYPTION_SERVICE))
			{
				java.util.Hashtable params = new java.util.Hashtable();
				params.put("returnObject", new Boolean(returnObject));
				amdocs.uamsimpl.shared.utils.debug.DebugLog.log(amdocs.uams.log.UamsLog.S_UAMS_TRACE, amdocs.uams.log.UamsLog.F_UAMS_ENCRYPTION_SERVICE, "method exit", params);
			}
		
			return returnObject;
		}
	}

}
