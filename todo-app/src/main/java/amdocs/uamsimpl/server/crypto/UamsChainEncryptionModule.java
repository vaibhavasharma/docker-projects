package amdocs.uamsimpl.server.crypto;

import amdocs.uams.module.UamsAbstractModule;
import amdocs.uams.module.UamsModuleManagmentContext;
import amdocs.uams.module.UamsConfigProperties;
import amdocs.uams.crypto.UamsEncryptionService;
import amdocs.uams.UamsOperationException;
import amdocs.uams.UamsConfigurationException;
import amdocs.uams.UamsSecurityException;
import amdocs.uams.UamsErrorCodes;
import amdocs.uams.log.UamsLog;
import amdocs.uamsimpl.shared.service.text.StringMarkerService;
import amdocs.uamsimpl.shared.utils.debug.DebugLog;

/**
 * UAMS
 * User: PAVELP
 * Date: May 16, 2005
 */
public class UamsChainEncryptionModule extends UamsAbstractModule {

	/*static {
		System.out.println("ASM::CUST PF for cust encryption UamsChainEncryptionModule");
	}*/
	public static final String PN_CRYPTO_SERVICE = "crypto.service";
	public static final String PN_CRYPTO_MARKER = "crypto.marker";


	protected StringMarkerService marker = null;
	protected UamsEncryptionService delegate = null;

	public void init(UamsModuleManagmentContext ctx, UamsConfigProperties props) throws UamsOperationException {

		String name = props.getString (PN_CRYPTO_MARKER, null);
		if (name==null)
			throw new UamsConfigurationException("Service "+PN_CRYPTO_MARKER+" was not configured.");
		marker = (StringMarkerService)ctx.lookup(name);
		if (marker==null)
			throw new UamsConfigurationException("Service "+name+" was not found.");

		name = props.getString (PN_CRYPTO_SERVICE, null);
		if (name==null)
			throw new UamsConfigurationException("Service "+PN_CRYPTO_SERVICE+" was not configured.");
		delegate = (UamsEncryptionService)ctx.lookup(name);
		if (delegate==null)
			throw new UamsConfigurationException("Service "+name+" was not found.");

		super.init(ctx, props);
	}

	public void terminate() throws UamsOperationException {
		super.terminate();
		delegate = null;
		marker = null;
	}

	protected class ChainEncryptionService implements UamsEncryptionService {

		public String encryptMsg(Object session, String resourceName, byte[] message)
				throws UamsSecurityException, UamsOperationException {

			return delegate.encryptMsg(session, resourceName, message);
		}

		public byte[] decryptMsg(Object session, String resourceName, String message) throws UamsSecurityException, UamsOperationException {
		//	System.out.println("ASM::CUST PF for decryptMsg UamsChainEncryptionModule$ChainEncryptionService");
			UamsDecryptionUtil decryptionUtil= new UamsDecryptionUtil();
			boolean useCustEncryption = UamsDecryptionUtil.isCUST_ENCRYPTION_ENABLED();
			if (useCustEncryption == true){
				return	decryptionUtil.custDecrypt(message).getBytes();
			}
			else {
				Markers first = getMarkers(session, resourceName, message, 0);

				if (first==null){
					UamsOperationException oe = new UamsOperationException(UamsErrorCodes.EC_1600001,new String [] {session+"",resourceName});
					DebugLog.log(UamsLog.S_UAMS_ERROR, UamsLog.F_UAMS_ENCRYPTION_SERVICE, oe);
					throw oe;
				}
				return chainDecryptMsg(session, resourceName, message, first);
			}
		}

		public byte[] chainDecryptMsg(Object session, String resourceName, String message, Markers markers)
				throws UamsSecurityException, UamsOperationException
		{

			if (markers==null){
				return message.getBytes();
			}

			String starting = message.substring(0, markers.getStart());
			String encrypted = message.substring(markers.getStart(), markers.getEnd());
			String remaining = message.substring(markers.getEnd(), message.length());

			byte[] decrypted = delegate.decryptMsg(session, resourceName, encrypted);
			byte[] startBytes = starting.getBytes();
			byte[] half = new byte[decrypted.length+startBytes.length];
			System.arraycopy(startBytes, 0, half, 0, startBytes.length);
			System.arraycopy(decrypted, 0, half, startBytes.length, decrypted.length);

			if (remaining.length()==0){
				return half;
			}

			Markers next = getMarkers(session, resourceName, remaining, markers.getEnd());
			byte[] endBytes = null;
			if (next==null){
				endBytes = remaining.getBytes();
			}
			else {
				endBytes = chainDecryptMsg(session, resourceName, remaining, next);
			}

			byte[] all = new byte[half.length+endBytes.length];
			System.arraycopy(half, 0, all, 0, half.length);
			System.arraycopy(endBytes, 0, all, half.length, endBytes.length);

			return all;
		}

		public boolean isEncrypted(Object session, String resourceName, String message)
				throws UamsSecurityException, UamsOperationException
		{
		//	System.out.println("ASM::CUST PF for isEncrypted UamsChainEncryptionModule$ChainEncryptionService");
			UamsDecryptionUtil decryptionUtil = new UamsDecryptionUtil();
			boolean useCustEncryption = UamsDecryptionUtil.isCUST_ENCRYPTION_ENABLED();
			if (useCustEncryption) {
				return (decryptionUtil.isCustEncrypted(message));

			} else {
				return (getMarkers(session, resourceName, message, 0) != null);
			}
		}

		private Markers getMarkers(Object session, String resourceName, String message, int from) throws UamsOperationException
		{
			String msgStart = marker.getStartMark();
			String msgEnd = marker.getEndMark();
			if (msgStart==null || msgEnd==null){
				return null;
			}

			int s1 = message.indexOf(msgStart, from);
			if (s1<0){
				return null;
			}
			int s2 = message.indexOf(msgStart, s1+msgStart.length());
			int e1 = message.indexOf(msgEnd, from);
			if (e1<0 || e1<s2){
				UamsOperationException oe = new UamsOperationException(UamsErrorCodes.EC_1600005,
						new String [] {session+"",resourceName});
				DebugLog.log(UamsLog.S_UAMS_ERROR, UamsLog.F_UAMS_ENCRYPTION_SERVICE, oe);
				throw oe;
			}

			return new Markers(s1, e1+msgEnd.length());
		}

	}

	class Markers {

		private int start, end;

		public Markers(int start, int end) {
			this.start = start;
			this.end = end;
		}

		public int getStart() {
			return start;
		}

		public int getEnd() {
			return end;
		}
	}
}
